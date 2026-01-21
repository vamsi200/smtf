#![allow(unused)]
use crate::{handshake::FatalExt, state::CondState};
use anyhow::{Error, Result};
use blake3::Hash;
use log::info;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc, Mutex,
    },
};

use crate::{
    crypto::{decrypt_data, encrypt_data},
    handshake::{receive_nonce, send_nonce},
    helper::PREHASH_LIMIT,
    state::{FileMetadata, ReceiverState, SenderEvent, TransferProgress, UiError},
};

use std::sync::Condvar;

enum MsgType {
    Data = 1,
    Eof = 2,
    Error = 3,
}

fn read_error(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 1];
    let _ = stream.read_exact(&mut buf);
    match buf[0] {
        3 => true,
        _ => false,
    }
}

fn write_error(stream: &mut TcpStream) {
    stream.write_all(&[MsgType::Error as u8]);
}

pub fn send_file(
    file: &mut File,
    stream: &mut TcpStream,
    sender_key: [u8; 32],
    hash: Option<Hash>,
    ev_tx: Sender<SenderEvent>,
    cancel: &Arc<AtomicBool>,
    state: &Arc<(Mutex<CondState>, Condvar)>,
    is_pause: &Arc<AtomicBool>,
) -> (Hash, Outcome) {
    let mut buf = [0u8; 64];
    let mut hasher = blake3::Hasher::new();

    file.seek(SeekFrom::Start(0)).expect("Failed to seek");
    let file_size = file.metadata().unwrap().len();

    let mut delta = 0usize;
    let mut result = Outcome::Completed;
    let mut stream_clone = stream.try_clone().unwrap();
    let mut ev_tx_clone = ev_tx.clone();

    std::thread::spawn(move || {
        let s = read_error(&mut stream_clone);
        if s {
            ev_tx_clone.send(SenderEvent::Error(UiError::ConnectionFailed)); // This context of error is fine, for now..
            return;
        }
    });

    if hash.is_none() {
        while let Ok(n) = file.read(&mut buf) {
            if cancel.load(Ordering::Relaxed) {
                result = Outcome::Cancelled;
                break;
            }

            if is_pause.load(Ordering::Relaxed) {
                let (lock, condvar) = &**state;
                let mut state = lock.lock().unwrap();

                while state.pause && !state.error {
                    state = condvar.wait(state).unwrap();
                }

                if state.error {
                    break;
                }
            }
            if n == 0 {
                if stream
                    .write_all(&[MsgType::Eof as u8])
                    .fatal(&ev_tx, |m| UiError::TransferFailed(m))
                    .is_none()
                {
                    result = Outcome::Error;

                    break;
                }
                break;
            }

            hasher.update(&buf[..n]);
            delta += n;

            ev_tx.send(SenderEvent::Trasnfer(TransferProgress {
                total: file_size,
                sent: delta,
            }));

            let (encrypted_chunks, nonce) = encrypt_data(sender_key, &buf[..n]);

            if stream
                .write_all(&[MsgType::Data as u8])
                .fatal(&ev_tx, |m| UiError::TransferFailed(m))
                .is_none()
            {
                result = Outcome::Error;

                break;
            }

            if send_nonce(stream, nonce)
                .fatal(&ev_tx, |m| UiError::NonceSendFailed(m))
                .is_none()
            {
                result = Outcome::Error;

                break;
            }

            let len = encrypted_chunks.len() as u32;
            if stream
                .write_all(&len.to_be_bytes())
                .fatal(&ev_tx, |m| UiError::TransferFailed(m))
                .is_none()
            {
                result = Outcome::Error;

                break;
            }

            if stream
                .write_all(&encrypted_chunks)
                .fatal(&ev_tx, |m| UiError::TransferFailed(m))
                .is_none()
            {
                result = Outcome::Error;

                break;
            }
        }
    } else {
        loop {
            let n = match file
                .read(&mut buf)
                .fatal(&ev_tx, |m| UiError::TransferFailed(m))
            {
                Some(n) => n,
                None => break,
            };

            if is_pause.load(Ordering::Relaxed) {
                let (lock, condvar) = &**state;
                let mut state = lock.lock().unwrap();

                while state.pause && !state.error {
                    state = condvar.wait(state).unwrap();
                }

                if state.error {
                    break;
                }
            }

            if n == 0 {
                if stream
                    .write_all(&[MsgType::Eof as u8])
                    .fatal(&ev_tx, |m| UiError::TransferFailed(m))
                    .is_none()
                {
                    result = Outcome::Error;
                    break;
                }
                break;
            }

            delta += n;

            ev_tx.send(SenderEvent::Trasnfer(TransferProgress {
                total: file_size,
                sent: delta,
            }));

            let (encrypted_chunks, nonce) = encrypt_data(sender_key, &buf[..n]);

            if stream
                .write_all(&[MsgType::Data as u8])
                .fatal(&ev_tx, |m| UiError::TransferFailed(m))
                .is_none()
            {
                result = Outcome::Error;

                break;
            }

            if send_nonce(stream, nonce)
                .fatal(&ev_tx, |m| UiError::NonceSendFailed(m))
                .is_none()
            {
                result = Outcome::Error;

                break;
            }

            let len = encrypted_chunks.len() as u32;
            if stream
                .write_all(&len.to_be_bytes())
                .fatal(&ev_tx, |m| UiError::TransferFailed(m))
                .is_none()
            {
                result = Outcome::Error;

                break;
            }

            if stream
                .write_all(&encrypted_chunks)
                .fatal(&ev_tx, |m| UiError::TransferFailed(m))
                .is_none()
            {
                result = Outcome::Error;

                break;
            }
        }
    }

    let final_hash = hash.unwrap_or_else(|| hasher.finalize());
    (final_hash, result)
}

pub enum Outcome {
    Completed,
    Cancelled,
    Error,
}

pub fn receive_file(
    stream: &mut TcpStream,
    receiver_key: [u8; 32],
    file: &mut File,
    ev_tx: &Sender<ReceiverState>,
    cancel: &Arc<AtomicBool>,
    is_pause: &Arc<AtomicBool>,
    state: &Arc<(Mutex<CondState>, Condvar)>,
) -> Result<Outcome, Error> {
    let mut delta: usize = 0;
    let mut result = Outcome::Completed;

    loop {
        let mut msg = [0u8; 1];

        if stream
            .read_exact(&mut msg)
            .fatal(ev_tx, UiError::ConnectionLost)
            .is_none()
        {
            result = Outcome::Error;
            break;
        }

        if is_pause.load(Ordering::Relaxed) {
            let (lock, condvar) = &**state;
            let mut state = lock.lock().unwrap();

            while state.pause && !state.error {
                state = condvar.wait(state).unwrap();
            }

            if state.error {
                let _ = write_error(stream);
                break;
            }
        }

        if cancel.load(Ordering::Relaxed) {
            result = Outcome::Cancelled;
            break;
        }

        match msg[0] {
            2 => break,

            1 => {
                let nonce = match receive_nonce(stream).fatal(ev_tx, UiError::NonceReceiveFailed) {
                    Some(n) => n,
                    None => {
                        result = Outcome::Error;
                        break;
                    }
                };

                let mut encrypted_chunk_len = [0u8; 4];

                if stream
                    .read_exact(&mut encrypted_chunk_len)
                    .fatal(ev_tx, UiError::ChunkLengthReceiveFailed)
                    .is_none()
                {
                    result = Outcome::Error;
                    break;
                }

                let encrypted_buf_len = u32::from_be_bytes(encrypted_chunk_len) as usize;

                if encrypted_buf_len == 0 {
                    break;
                }

                let mut buf = vec![0u8; encrypted_buf_len];

                if stream
                    .read_exact(&mut buf)
                    .fatal(ev_tx, UiError::ChunkReceiveFailed)
                    .is_none()
                {
                    result = Outcome::Error;
                    break;
                }

                let decrypted = decrypt_data(buf, nonce, receiver_key);
                delta += decrypted.len();

                ev_tx.send(ReceiverState::ReceivedBytes(delta));

                if file
                    .write_all(&decrypted)
                    .fatal(ev_tx, UiError::FileWriteFailed)
                    .is_none()
                {
                    result = Outcome::Error;
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(result)
}

pub fn send_file_metadata(stream: &mut TcpStream, metadata: FileMetadata) -> Result<(), Error> {
    let name_len = metadata.name.len() as u16;
    stream.write_all(&name_len.to_be_bytes())?;
    stream.write_all(&metadata.name.as_bytes())?;

    let size = metadata.size.len() as u16;
    stream.write_all(&size.to_be_bytes())?;
    stream.write_all(&metadata.size.as_bytes())?;

    let raw_size = metadata.raw_bytes.to_be_bytes().len();
    stream.write_all(&raw_size.to_be_bytes())?;
    stream.write_all(&metadata.raw_bytes.to_be_bytes())?;

    let file_type = metadata.file_type.len() as u16;
    stream.write_all(&file_type.to_be_bytes())?;
    stream.write_all(&metadata.file_type.as_bytes())?;

    let path = metadata.path.len() as u16;
    stream.write_all(&path.to_be_bytes())?;
    stream.write_all(&metadata.path.as_bytes())?;

    let modified_date = metadata.modified_date.len() as u16;
    stream.write_all(&modified_date.to_be_bytes())?;
    stream.write_all(&metadata.modified_date.as_bytes())?;

    Ok(())
}

pub fn receive_metadata(stream: &mut TcpStream) -> Result<FileMetadata, Error> {
    let mut len = [0u8; 2];

    stream.read_exact(&mut len)?;
    let name_len = u16::from_be_bytes(len) as usize;
    let mut name = vec![0u8; name_len];
    stream.read_exact(&mut name)?;

    stream.read_exact(&mut len)?;
    let size_len = u16::from_be_bytes(len) as usize;
    let mut size = vec![0u8; size_len];
    stream.read_exact(&mut size)?;

    let mut raw_size_buf = [0u8; 8];
    stream.read_exact(&mut raw_size_buf)?;
    let size_len = u64::from_be_bytes(raw_size_buf) as usize;
    let mut raw_size = vec![0u8; size_len];
    stream.read_exact(&mut raw_size)?;

    stream.read_exact(&mut len)?;
    let file_type_len = u16::from_be_bytes(len) as usize;
    let mut file_type = vec![0u8; file_type_len];
    stream.read_exact(&mut file_type)?;

    stream.read_exact(&mut len)?;
    let path_len = u16::from_be_bytes(len) as usize;
    let mut path = vec![0u8; path_len];
    stream.read_exact(&mut path)?;

    stream.read_exact(&mut len)?;
    let modified_date_len = u16::from_be_bytes(len) as usize;
    let mut modified_date = vec![0u8; modified_date_len];
    stream.read_exact(&mut modified_date)?;

    let name = String::from_utf8(name)?;
    let size = String::from_utf8(size)?;
    let file_type = String::from_utf8(file_type)?;
    let path = String::from_utf8(path)?;
    let modified_date = String::from_utf8(modified_date)?;

    let try_u64: [u8; 8] = raw_size.try_into().expect("buffer size must be of 8 bytes");
    let raw_bytes = u64::from_be_bytes(try_u64);

    Ok(FileMetadata {
        name: name,
        size: size,
        raw_bytes: raw_bytes,
        file_type: file_type,
        path: path,
        modified_date: modified_date,
    })
}

enum HashType {
    Some = 1,
    None = 0,
}
// Blake3 hash len is 32.. so.
pub fn send_hash(hash: Option<Hash>, stream: &mut TcpStream) -> Result<(), Error> {
    match hash {
        Some(hash) => {
            let hash_type_val = HashType::Some as u8;
            stream.write_all(&[hash_type_val]);
            stream.write_all(hash.as_bytes())?;
        }
        None => {
            let hash_type_val = HashType::None as u8;
            stream.write_all(&[hash_type_val]);
        }
    }
    Ok(())
}

pub fn receive_hash(stream: &mut TcpStream) -> Result<Option<Hash>, Error> {
    let mut hash_type = [0u8; 1];
    stream.read_exact(&mut hash_type)?;
    let hash = match hash_type[0] {
        1 => {
            let mut hash = [0u8; 32];
            stream.read_exact(&mut hash)?;

            Some(Hash::from_bytes(hash))
        }
        0 => None,
        _ => None,
    };
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn localhost_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        (client, server)
    }

    #[test]
    fn metadata_roundtrip() {
        let (mut sender, mut receiver) = localhost_pair();

        let metadata = FileMetadata {
            name: "example.txt".into(),
            size: "123456".into(),
            raw_bytes: 123456,
            file_type: "text/plain".into(),
            path: "/home/user/example.txt".into(),
            modified_date: "2026-01-10".into(),
        };

        let sender_md = metadata.clone();

        let sender_thread = thread::spawn(move || {
            send_file_metadata(&mut sender, sender_md).unwrap();
        });

        let received = receive_metadata(&mut receiver).unwrap();

        sender_thread.join().unwrap();

        assert_eq!(received, metadata);
    }

    #[test]
    fn metadata_empty_fields() {
        let (mut sender, mut receiver) = localhost_pair();

        let metadata = FileMetadata {
            name: "".into(),
            size: "".into(),
            raw_bytes: 0,
            file_type: "".into(),
            path: "".into(),
            modified_date: "".into(),
        };

        let sender_md = metadata.clone();

        let sender_thread = thread::spawn(move || {
            send_file_metadata(&mut sender, sender_md).unwrap();
        });

        let received = receive_metadata(&mut receiver).unwrap();

        sender_thread.join().unwrap();

        assert_eq!(received, metadata);
    }

    #[test]
    fn hash_some_roundtrip() {
        let (mut sender, mut receiver) = localhost_pair();

        let hash = blake3::hash(b"important data");

        let sender_thread = thread::spawn(move || {
            send_hash(Some(hash), &mut sender).unwrap();
        });

        let received = receive_hash(&mut receiver).unwrap();

        sender_thread.join().unwrap();

        assert_eq!(received, Some(hash));
    }

    #[test]
    fn hash_none_roundtrip() {
        let (mut sender, mut receiver) = localhost_pair();

        let sender_thread = thread::spawn(move || {
            send_hash(None, &mut sender).unwrap();
        });

        let received = receive_hash(&mut receiver).unwrap();

        sender_thread.join().unwrap();

        assert_eq!(received, None);
    }

    #[test]
    fn invalid_hash_flag_is_handled() {
        let (mut sender, mut receiver) = localhost_pair();

        let sender_thread = thread::spawn(move || {
            sender.write_all(&[0xFF]).unwrap();
        });

        let received = receive_hash(&mut receiver).unwrap();

        sender_thread.join().unwrap();

        assert_eq!(received, None);
    }
}
