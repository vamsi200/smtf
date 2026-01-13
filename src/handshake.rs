#![allow(dead_code)]
#![allow(unused)]

use anyhow::{Error, Result};
use chacha20poly1305::Nonce;
use egui::text_selection::LabelSelectionState;
use log::{error, info, log};
use rand::RngCore;
use rand::{rngs::OsRng, TryRngCore};
use rfd::FileDialog;
use sha2::{Digest, Sha256};
use std::env::Args;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{
    Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroize;

use crate::crypto::{self, derive_session_keys, encrypt_data, Mode, SessionKeys};

pub struct HandShakeData {
    public_key: PublicKey,
    private_key: EphemeralSecret,
}

#[derive(Debug, Clone)]
pub struct TransferCode {
    socket_addr: SocketAddr,
    pub secret: Vec<u8>,
}

type RawTransferCode = String;
type HumanReadableTransferCode = String;

// Sender
pub fn generate_key_state() -> HandShakeData {
    let sender_private_key = EphemeralSecret::random();
    let sender_public_key = PublicKey::from(&sender_private_key);

    HandShakeData {
        public_key: sender_public_key,
        private_key: sender_private_key,
    }
}

pub fn derive_shared_secret(
    private_key: EphemeralSecret,
    peer_public_key: PublicKey,
) -> SharedSecret {
    private_key.diffie_hellman(&peer_public_key)
}

pub fn derive_transcript(
    sender_public_key: PublicKey,
    receiver_public_key: PublicKey,
    secret: &Vec<u8>,
) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"SMTF/1.0");
    hash.update(sender_public_key.as_bytes());
    hash.update(receiver_public_key.as_bytes());
    hash.update(secret.clone());
    hash.finalize().to_vec()
}

// Receiver
pub fn generate_receiver_key_state() -> HandShakeData {
    todo!()
}

pub fn gen_human_readable_transfer_code(encoded_data: &str) -> String {
    encoded_data
        .as_bytes()
        .chunks(4)
        .map(|c| str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn parse_transfer_code(transfer_code: &String) -> RawTransferCode {
    if transfer_code.contains("-") {
        transfer_code
            .split_terminator('-')
            .into_iter()
            .collect::<Vec<_>>()
            .concat()
    } else {
        eprintln!("Invalid Secret");
        exit(1); // do something else..
    }
}

// Sender
pub fn encode(socket: SocketAddr) -> Result<HumanReadableTransferCode, Error> {
    let mut secret = [0u8; 16];
    OsRng.try_fill_bytes(&mut secret)?;
    let mut socket_bytes = format!("{}", socket).into_bytes();
    for s in secret {
        socket_bytes.extend_from_slice(&[s])
    }
    let bytes_encoded = base32::encode(base32::Alphabet::Crockford, &socket_bytes);
    let human_transfer_code = gen_human_readable_transfer_code(&bytes_encoded);

    Ok(human_transfer_code)
}

// Receiver
pub fn decode(encoded_data: &HumanReadableTransferCode) -> Result<TransferCode, Error> {
    let raw = parse_transfer_code(encoded_data);
    let mut s = base32::decode(base32::Alphabet::Crockford, &raw)
        .expect("Failed to decode, invalid secret");
    let pos = s.len() - 16;
    let split = s.split_at(pos);
    let socket_addr_str = str::from_utf8(split.0).unwrap();
    let socket_addr = socket_addr_str.to_socket_addrs().unwrap().next().unwrap();
    let secret = split.1.to_owned();

    let transfer_code = TransferCode {
        socket_addr: socket_addr,
        secret: secret,
    };

    Ok(transfer_code)
}

type Connection = (TcpStream, SocketAddr);

use crate::helper::{get_file_hash, get_file_metadata, get_socket_addr, PREHASH_LIMIT};
use crate::state::{
    self, BackendState, Command, FileHash, FileMetadata, HandShakeState, HandshakeData,
    ReceiveHandShakeState, ReceiverState, ReceiverTask, ReceiverUiState, SenderEvent, Task,
    TransferProgress,
};
use crate::transfer::{
    self, receive_file, receive_hash, receive_metadata, send_file, send_file_metadata, send_hash,
};

// Sender
pub fn sender(ev_tx: mpsc::Sender<SenderEvent>, file_path: PathBuf) -> Result<Task, Error> {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();

    let cwd = std::env::current_dir().expect("error");
    let socket_addr = get_socket_addr().expect("error");
    let secret_code = encode(socket_addr).expect("error");
    let transfer_code = decode(&secret_code).expect("error");

    ev_tx.send(SenderEvent::HandshakeState(HandShakeState::Initialzed));

    let handshake_data = HandshakeData {
        cwd: cwd,
        socket_addr: socket_addr,
        secrte_code: secret_code,
        transfer_code: transfer_code.clone(),
        file_path: file_path.clone(),
    };

    let mut buf = [0u8; 17];
    let mut file = File::open(&file_path)?;
    let file_size = file.metadata().expect("Failed to get file metadata").len();
    let file_metadata = get_file_metadata(&file, &file_path)?;
    let socket_addr = socket_addr;
    let listener = TcpListener::bind(socket_addr).expect("Failed to start the listener");
    let file_size_bytes = file.metadata().unwrap().len();

    ev_tx.send(SenderEvent::HandshakeState(HandShakeState::Secret));
    ev_tx.send(SenderEvent::FileData(file_metadata.clone()));

    info!("listener started - {}", listener.local_addr()?);

    let hash = if file_size > PREHASH_LIMIT {
        // at this point send a popup to the user that we will be computing hash sequentially..
        info!("File is huge..");
        ev_tx
            .send(SenderEvent::FileHash(FileHash { hash: None }))
            .inspect_err(|e| eprintln!("{e}"));
        None
    } else {
        let file_hash = get_file_hash(&mut file)?;
        info!("Sending the File Hash to gui channel..");
        ev_tx.send(SenderEvent::FileHash(FileHash {
            hash: Some(file_hash.clone()),
        }));
        Some(file_hash)
    };

    ev_tx
        .send(SenderEvent::HandshakeDerived(handshake_data))
        .inspect_err(|e| eprintln!("{e}"));

    listener.set_nonblocking(true)?;
    let handle = std::thread::spawn(move || {
        loop {
            if cancel_clone.load(Ordering::Relaxed) {
                info!("Sender cancelled, shutting down listener");
                break;
            }

            match listener.accept() {
                Ok((mut stream, addr)) => {
                    info!("Client connected: {addr}");

                    if cancel_clone.load(Ordering::Relaxed) {
                        let _ = stream.shutdown(Shutdown::Both);
                        break;
                    }

                    if verify_secret(&mut stream, &transfer_code).unwrap_or(false) {
                        let state = generate_key_state();
                        send_public_key(&mut stream, &state.public_key).ok();

                        if let Ok(peer_pk) = receive_public_key(&mut stream) {
                            info!("Deriving secret..");
                            let shared_secret = derive_shared_secret(state.private_key, peer_pk);

                            info!("Deriving transcript..");
                            let transcript =
                                derive_transcript(state.public_key, peer_pk, &transfer_code.secret);

                            info!("Deriving session keys..");
                            let session_keys =
                                derive_session_keys(&shared_secret, &transcript, Mode::Sender)
                                    .expect("Failed to derive keys");

                            ev_tx.send(SenderEvent::HandshakeState(HandShakeState::Handshake));

                            info!("Sending File Metatdata..");
                            if let Ok(_) = send_file_metadata(&mut stream, file_metadata) {
                                info!("Sending hash to the receiver..");
                                send_hash(hash, &mut stream);

                                let decision =
                                    receive_decision(&mut stream).expect("Failed to get decision");
                                match decision {
                                    Decision::Accept => {
                                        ev_tx.send(SenderEvent::HandshakeState(
                                            HandShakeState::Sending,
                                        ));
                                        let file_hash = send_file(
                                            &mut file,
                                            &mut stream,
                                            session_keys.sender_key,
                                            hash,
                                            ev_tx.clone(),
                                        );

                                        ev_tx.send(SenderEvent::HandshakeState(
                                            HandShakeState::Completed,
                                        ));

                                        if hash.is_none() {
                                            info!(
                                        "File exceeded the pre-hash limit, sending the hash now.."
                                        );
                                            send_hash(Some(file_hash), &mut stream);
                                            let file_hash = FileHash {
                                                hash: Some(file_hash),
                                            };
                                            ev_tx.send(SenderEvent::FileHash(file_hash));
                                        }
                                    }
                                    Decision::Reject => {
                                        info!("Receiver cancelled the file send!");
                                        let _ = stream.shutdown(Shutdown::Both);
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }

                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }

                Err(e) => {
                    error!("Listener error: {e}");
                    break;
                }
            }
        }

        info!("Sender thread exiting cleanly");
    });

    Ok(Task {
        cancel: cancel,
        handle: handle,
    })
}

const NONCE_LEN: usize = 12;

pub fn send_nonce(stream: &mut TcpStream, nonce: Nonce) -> Result<(), Error> {
    assert_eq!(NONCE_LEN, nonce.len());
    stream.write_all(&nonce.to_vec())?;
    stream.flush()?;
    Ok(())
}

pub fn receive_nonce(stream: &mut TcpStream) -> Result<Nonce, Error> {
    let mut buf = vec![0u8; NONCE_LEN];
    stream.read_exact(&mut buf)?;
    Ok(Nonce::from_slice(&buf).to_owned())
}

pub fn send_public_key(stream: &mut TcpStream, public_key: &PublicKey) -> Result<(), Error> {
    let public_key = public_key.as_bytes();

    let len = public_key.len() as u16;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(public_key)?;

    Ok(())
}

pub fn receive_public_key(stream: &mut TcpStream) -> Result<PublicKey, Error> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len != 32 {
        return Err(Error::msg("Invalid public key length!"));
    }

    let mut buf = [0u8; 32];
    stream.read_exact(&mut buf)?;

    Ok(PublicKey::from(buf))
}

pub fn send_secret(stream: &mut TcpStream, secret: Vec<u8>) -> Result<(), Error> {
    stream.write_all(&[0x01])?;
    stream.write_all(&(secret.len() as u16).to_be_bytes())?;
    stream.write_all(&secret)?;
    Ok(())
}

pub fn verify_secret(stream: &mut TcpStream, transfer_code: &TransferCode) -> Result<bool, Error> {
    let mut t = [0u8; 1];
    stream.read_exact(&mut t)?;
    assert_eq!(t[0], 0x01);

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;

    let verify = if buf != transfer_code.secret {
        println!("Secret is wrong bro!");
        false
    } else {
        info!("Successfully verified secret!");
        true
    };
    Ok(verify)
}

// Receiver
pub fn start_receiver(
    transfer_code: TransferCode,
    cmd_tx: Sender<ReceiverState>,
    decision_rx: Receiver<Decision>,
    ui_tx: Sender<ReceiverUiState>,
) {
    let socket_addr = transfer_code.socket_addr;
    let secret = transfer_code.secret;

    if let Ok(mut stream) = TcpStream::connect(socket_addr) {
        info!("Connected to {socket_addr:?}");

        cmd_tx.send(ReceiverState::HandshakeState(
            ReceiveHandShakeState::Initialized,
        ));

        if let Ok(_) = send_secret(&mut stream, secret.clone()) {
            info!("Trying to get Sender's PublicKey");

            let state = generate_key_state();
            if let Ok(peer_public_key) = receive_public_key(&mut stream) {
                assert_ne!(peer_public_key.as_bytes(), state.public_key.as_bytes());

                cmd_tx.send(ReceiverState::HandshakeState(
                    ReceiveHandShakeState::PublicKeyReceived,
                ));

                info!("PublicKey received successfully!");

                if let Ok(_) = send_public_key(&mut stream, &state.public_key) {
                    info!("PublicKey sent successfully!");

                    cmd_tx.send(ReceiverState::HandshakeState(
                        ReceiveHandShakeState::PublicKeySent,
                    ));

                    let shared_secret = derive_shared_secret(state.private_key, peer_public_key);

                    cmd_tx.send(ReceiverState::HandshakeState(
                        ReceiveHandShakeState::DeriveSharedSecret,
                    ));

                    let transcript = derive_transcript(peer_public_key, state.public_key, &secret);

                    info!("Derived Transcript..");

                    cmd_tx.send(ReceiverState::HandshakeState(
                        ReceiveHandShakeState::DeriveTranscript,
                    ));

                    let session_keys =
                        derive_session_keys(&shared_secret, &transcript, Mode::Receiver)
                            .expect("error");

                    info!("Derived Session Keys");

                    cmd_tx.send(ReceiverState::HandshakeState(
                        ReceiveHandShakeState::DeriveSessionKeys,
                    ));

                    if let Ok(file_metadata) = receive_metadata(&mut stream) {
                        let hash = receive_hash(&mut stream).expect("error");
                        let hash_state = FileHash { hash: hash };

                        cmd_tx.send(ReceiverState::FileHash(hash_state));

                        info!("Received File Metatdata");
                        cmd_tx.send(ReceiverState::FileState(file_metadata.clone()));

                        let file_name = file_metadata.name;

                        ui_tx.send(ReceiverUiState::Confirming);

                        while let Ok(decision) = decision_rx.recv() {
                            match decision {
                                Decision::Accept => {
                                    if let Some(file_path) = FileDialog::new()
                                        .set_title("Save File")
                                        .set_file_name(file_name.clone())
                                        .save_file()
                                    {
                                        if let Ok(_) = send_decision(&mut stream, Decision::Accept)
                                        {
                                            ui_tx.send(ReceiverUiState::Receiving);
                                            let mut file = File::create(file_path).expect("error");
                                            cmd_tx.send(ReceiverState::RecieveStarted);

                                            if let Ok(_) = receive_file(
                                                &mut stream,
                                                session_keys.receiver_key,
                                                &mut file,
                                                &cmd_tx,
                                            ) {
                                                cmd_tx.send(ReceiverState::RecieveCompleted);
                                                if hash.is_none() {
                                                    info!("File exceeded the pre-hash limit, Trying to recieve the hash..");
                                                    let hash =
                                                        receive_hash(&mut stream).expect("error");
                                                    let hash_state = FileHash { hash: hash };
                                                    cmd_tx
                                                        .send(ReceiverState::FileHash(hash_state));
                                                }
                                            }
                                        }
                                    }
                                }
                                Decision::Reject => {
                                    send_decision(&mut stream, Decision::Reject)
                                        .expect("failed to send decision");
                                    stream.shutdown(Shutdown::Both);
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        println!("Couldn't connect bro..");
    }
}

#[repr(u8)]
pub enum Decision {
    Accept = 1,
    Reject = 0,
}

fn send_decision(stream: &mut TcpStream, decision: Decision) -> Result<(), std::io::Error> {
    stream.write_all(&[decision as u8])?;
    stream.flush()?;
    Ok(())
}

fn receive_decision(stream: &mut TcpStream) -> Result<Decision, std::io::Error> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;

    match buf[0] {
        0 => Ok(Decision::Reject),
        1 => Ok(Decision::Accept),
        v => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid decision byte: {}", v),
        )),
    }
}

pub fn receiver(
    transfer_code: TransferCode,
    rec_tx: Sender<ReceiverState>,
    ui_tx: Sender<ReceiverUiState>,
) -> Result<ReceiverTask, Error> {
    let (decision_tx, decision_rx) = std::sync::mpsc::channel();

    let handle =
        std::thread::spawn(move || start_receiver(transfer_code, rec_tx, decision_rx, ui_tx));

    Ok(ReceiverTask {
        handle: handle,
        decision_tx: decision_tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decrypt_data, encrypt_data};
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::thread;
    fn test_socket_addr() -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 4242, 0, 0))
    }

    #[test]
    fn test_send_and_receive_public_key() {
        let socket_addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0);
        let listener = TcpListener::bind(socket_addr).unwrap();
        let addr = listener.local_addr().unwrap();
        let state = generate_key_state();
        let public_key = state.public_key;

        thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            send_public_key(&mut stream, &public_key).unwrap();
        });

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let pk = receive_public_key(&mut stream).unwrap();
            assert_eq!(pk.as_bytes(), public_key.as_bytes());
            assert_eq!(pk.as_bytes().len(), public_key.as_bytes().len());
        });
    }

    #[test]
    fn test_shared_secret() {
        let sender_state = generate_key_state();
        let receiver_state = generate_key_state();
        let mut sender_shared_secret =
            derive_shared_secret(sender_state.private_key, receiver_state.public_key);
        let mut receiver_shared_secret =
            derive_shared_secret(receiver_state.private_key, sender_state.public_key);

        assert_eq!(
            sender_shared_secret.as_bytes(),
            receiver_shared_secret.as_bytes()
        );
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let sender_state = generate_key_state();
        let receiver_state = generate_key_state();
        let data = vec![8, 2, 4, 6, 8];
        let secret = vec![3, 42, 42, 32, 12];

        let mut shared_secret =
            derive_shared_secret(sender_state.private_key, receiver_state.public_key);

        let hash = derive_transcript(sender_state.public_key, receiver_state.public_key, &secret);

        let sender_keys = derive_session_keys(&shared_secret, &hash, Mode::Sender)
            .expect("Failed to derive keys");
        let receiver_keys = derive_session_keys(&shared_secret, &hash, Mode::Receiver)
            .expect("Failed to derive keys");

        shared_secret.zeroize();

        let (ct, nonce) = encrypt_data(sender_keys.sender_key, &data);
        let decrypted_text = decrypt_data(ct.clone(), nonce, receiver_keys.receiver_key);

        assert_ne!(data, ct);
        assert_eq!(data, decrypted_text)
    }

    #[test]
    fn test_human_readable_roundtrip() {
        let raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        let human = gen_human_readable_transfer_code(raw);
        let parsed = parse_transfer_code(&human);
        assert_eq!(raw, parsed);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let socket = test_socket_addr();
        let encoded = encode(socket).expect("encode failed");

        let raw = parse_transfer_code(&encoded);
        let decoded = decode(&raw).expect("decode failed");

        assert_eq!(decoded.socket_addr, socket);
        assert_eq!(decoded.secret.len(), 16);
    }

    #[test]
    fn test_secret_is_random() {
        let socket = test_socket_addr();

        let code1 = encode(socket).unwrap();
        let code2 = encode(socket).unwrap();

        let raw1 = parse_transfer_code(&code1);
        let raw2 = parse_transfer_code(&code2);

        let d1 = decode(&raw1).unwrap();
        let d2 = decode(&raw2).unwrap();

        assert_ne!(d1.secret, d2.secret, "Secrets should be random");
    }

    #[test]
    fn test_transfer_code_contains_valid_socket() {
        let socket = test_socket_addr();
        let encoded = encode(socket).unwrap();

        let raw = parse_transfer_code(&encoded);
        let decoded = decode(&raw).unwrap();

        match decoded.socket_addr {
            SocketAddr::V6(v6) => {
                assert_eq!(v6.port(), 4242);
                assert_eq!(*v6.ip(), Ipv6Addr::LOCALHOST);
            }
            _ => panic!("Expected IPv6 socket addr"),
        }
    }

    #[test]
    fn test_base32_decode_length() {
        let socket = test_socket_addr();
        let encoded = encode(socket).unwrap();

        let raw = parse_transfer_code(&encoded);
        let decoded_bytes = base32::decode(base32::Alphabet::Crockford, &raw).unwrap();

        assert!(decoded_bytes.len() > 16);
    }
}
