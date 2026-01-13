#![allow(unused)]
use anyhow::{Error, Result};
use blake3::Hash;
use log::info;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    net::TcpStream,
    sync::{mpsc::Sender, Arc, Mutex},
};

use crate::{
    crypto::{decrypt_data, encrypt_data},
    handshake::{receive_nonce, send_nonce},
    helper::PREHASH_LIMIT,
    state::{FileMetadata, ReceiverState, SenderEvent, TransferProgress},
};

// to handle the Eof problem
enum MsgType {
    Data = 1,
    Eof = 2,
}

pub fn send_file(
    file: &mut File,
    stream: &mut TcpStream,
    sender_key: [u8; 32],
    hash: Option<Hash>,
    ev_tx: Sender<SenderEvent>,
) -> Hash {
    let mut buf = [0u8; 512 * 1024];
    let mut hasher = blake3::Hasher::new();
    file.seek(SeekFrom::Start(0)).expect("Failed to Seek");
    let file_size = file.metadata().unwrap().len();
    let mut delta = 0;

    // all this just to not check the hasher on every iteration
    if hash.is_none() {
        while let Ok(n) = file.read(&mut buf) {
            if n == 0 {
                let eof_msg = MsgType::Eof as u8;
                stream.write_all(&[eof_msg]);
                info!("Reached EOF, breaking...");
                break;
            }

            hasher.update(&mut buf[..n]);
            let plain_text_len = n as u32;
            delta += plain_text_len as usize;

            let transfer_progress = TransferProgress {
                total: file_size,
                sent: delta,
            };

            ev_tx.send(SenderEvent::Trasnfer(transfer_progress));
            let (encrypted_chunks, nonce) = encrypt_data(sender_key, &buf[..n]);

            let data_start = MsgType::Data as u8;
            stream.write_all(&[data_start]);
            send_nonce(stream, nonce).expect("Failed to send nonce");

            let encrypted_chunks_len = encrypted_chunks.len() as u32;
            stream.write_all(&encrypted_chunks_len.to_be_bytes());
            stream
                .write_all(&encrypted_chunks)
                .inspect_err(|e| eprintln!("{e}"))
                .unwrap();
        }
    } else {
        loop {
            let n = file.read(&mut buf).expect("failed to read file");
            if n == 0 {
                let eof_msg = MsgType::Eof as u8;
                stream.write_all(&[eof_msg]);
                info!("Reached EOF, breaking...");
                break;
            }

            let plain_text_len = n as u32;
            let (encrypted_chunks, nonce) = encrypt_data(sender_key, &buf[..n]);
            delta += plain_text_len as usize;

            let transfer_progress = TransferProgress {
                total: file_size,
                sent: delta,
            };
            ev_tx.send(SenderEvent::Trasnfer(transfer_progress));

            let data_start = MsgType::Data as u8;
            stream.write_all(&[data_start]);
            send_nonce(stream, nonce).expect("Failed to send nonce");

            let encrypted_chunks_len = encrypted_chunks.len() as u32;
            stream.write_all(&encrypted_chunks_len.to_be_bytes());
            stream
                .write_all(&encrypted_chunks)
                .inspect_err(|e| eprintln!("{e}"))
                .unwrap();
        }
    }

    let hash = if let Some(hash) = hash {
        hash
    } else {
        hasher.finalize()
    };

    hash
}

pub fn receive_file(
    stream: &mut TcpStream,
    receiver_key: [u8; 32],
    file: &mut File,
    ev_tx: &Sender<ReceiverState>,
) -> Result<(), Error> {
    let mut delta: usize = 0;

    loop {
        let mut msg = [0u8; 1];
        if stream.read_exact(&mut msg).is_err() {
            break;
        }

        match msg[0] {
            2 => {
                break;
            }
            1 => {
                let nonce = receive_nonce(stream).inspect_err(|e| eprintln!("{e}"))?;
                let mut encrypted_chunk_len = [0u8; 4];
                let mut plain_text_len = [0u8; 4];

                stream.read_exact(&mut encrypted_chunk_len)?;

                let encrypted_buf_len = u32::from_be_bytes(encrypted_chunk_len) as usize;

                if encrypted_buf_len == 0 {
                    break;
                }

                let mut buf = vec![0u8; encrypted_buf_len];
                stream.read_exact(&mut buf)?;

                let decrypted = decrypt_data(buf, nonce, receiver_key);
                delta += decrypted.len() as usize;

                ev_tx.send(ReceiverState::ReceivedBytes(delta));

                file.write_all(&decrypted)?;
            }
            _ => {}
        }
    }
    Ok(())
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
            // write an invalid flag
            sender.write_all(&[0xFF]).unwrap();
        });

        let received = receive_hash(&mut receiver).unwrap();

        sender_thread.join().unwrap();

        assert_eq!(received, None);
    }
}
