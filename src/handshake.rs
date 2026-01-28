use anyhow::{Error, Result};
use chacha20poly1305::Nonce;
use log::{error, info};
use rand::{rngs::OsRng, TryRngCore};
use rfd::FileDialog;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::crypto::{derive_session_keys, Mode};

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
    transfer_code
        .split_terminator('-')
        .into_iter()
        .collect::<Vec<_>>()
        .concat()
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
pub fn decode(encoded_data: &HumanReadableTransferCode) -> Option<TransferCode> {
    let raw = parse_transfer_code(encoded_data);
    let s = base32::decode(base32::Alphabet::Crockford, &raw);
    let transfer_code = if let Some(s) = s {
        if s.len() < 16 {
            return None;
        }
        let pos = s.len() - 16;
        let split = s.split_at(pos);
        let socket_addr_str = str::from_utf8(split.0).unwrap();
        let socket_addr = socket_addr_str.to_socket_addrs().unwrap().next().unwrap();
        let secret = split.1.to_owned();

        Some(TransferCode {
            socket_addr: socket_addr,
            secret: secret,
        })
    } else {
        return None;
    };

    transfer_code
}

use crate::helper::{get_file_hash, get_file_metadata, get_socket_addr, PREHASH_LIMIT};
use crate::state::{
    CondState, FileHash, HandshakeData, ReceiveHandShakeState, ReceiverNetworkInfo, ReceiverState,
    ReceiverTask, ReceiverUiState, SenderEvent, SenderHandShakeState, SenderNetworkInfo, Task,
    UiError,
};

use crate::transfer::{
    receive_file, receive_hash, receive_metadata, send_file, send_file_metadata, send_hash, Outcome,
};

pub trait ErrorSink {
    fn send_error(&self, err: UiError);
}

impl ErrorSink for Sender<ReceiverState> {
    fn send_error(&self, err: UiError) {
        let _ = self.send(ReceiverState::Error(err));
    }
}

impl ErrorSink for Sender<SenderEvent> {
    fn send_error(&self, err: UiError) {
        let _ = self.send(SenderEvent::Error(err));
    }
}

pub trait FatalExt<T> {
    fn fatal<S>(self, sink: &S, err: impl FnOnce(Option<String>) -> UiError) -> Option<T>
    where
        S: ErrorSink;
}

impl<T, E> FatalExt<T> for Result<T, E>
where
    E: std::fmt::Display,
{
    fn fatal<S>(self, sink: &S, err: impl FnOnce(Option<String>) -> UiError) -> Option<T>
    where
        S: ErrorSink,
    {
        match self {
            Ok(t) => Some(t),
            Err(e) => {
                sink.send_error(err(Some(e.to_string())));
                None
            }
        }
    }
}

macro_rules! fatal_or_return {
    ($expr:expr, $tx:expr, $err:expr) => {
        if $expr.fatal($tx, $err).is_none() {
            return;
        }
    };
}

// Sender
pub fn sender(
    ev_tx: mpsc::Sender<SenderEvent>,
    file_path: PathBuf,
    pause_cond: Arc<(Mutex<CondState>, Condvar)>,
) -> Result<Task, Error> {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();

    let pause = Arc::new(AtomicBool::new(false));
    let pause_clone = Arc::clone(&pause);

    let cwd = std::env::current_dir()?;
    let socket_addr = get_socket_addr()?;
    let secret_code = encode(socket_addr)?;
    let transfer_code = decode(&secret_code).unwrap(); // unwrap is fine here I guess..

    let sender_network_info = SenderNetworkInfo {
        ip: socket_addr.ip().to_string(),
        port: socket_addr.port().to_string(),
    };

    let _ = ev_tx.send(SenderEvent::SenderNetworkInfo(sender_network_info));

    let _ = ev_tx.send(SenderEvent::HandshakeState(
        SenderHandShakeState::Initialized,
    ));

    let _ = ev_tx.send(SenderEvent::HandshakeState(
        SenderHandShakeState::SecretDerived,
    ));

    let handshake_data = HandshakeData {
        cwd,
        socket_addr,
        secrte_code: secret_code,
        transfer_code: transfer_code.clone(),
        file_path: file_path.clone(),
    };

    let mut file = File::open(&file_path)?;
    let file_size = file.metadata()?.len();
    let file_metadata = get_file_metadata(&file, &file_path)?;

    let listener = TcpListener::bind(socket_addr)?;
    listener.set_nonblocking(true)?;

    let _ = ev_tx.send(SenderEvent::FileData(file_metadata.clone()));

    let hash = if file_size > PREHASH_LIMIT {
        let _ = ev_tx.send(SenderEvent::FileHash(FileHash { hash: None }));
        None
    } else {
        let h = get_file_hash(&mut file)?;
        let _ = ev_tx.send(SenderEvent::FileHash(FileHash {
            hash: Some(h.clone()),
        }));
        Some(h)
    };

    let _ = ev_tx.send(SenderEvent::HandshakeDerived(handshake_data));

    let handle = std::thread::spawn(move || {
        loop {
            if cancel_clone.load(Ordering::Relaxed) {
                break;
            }

            match listener.accept() {
                Ok((mut stream, addr)) => {
                    let receiver_network_info = ReceiverNetworkInfo {
                        ip: addr.ip().to_string(),
                        port: addr.port().to_string(),
                    };

                    let _ = ev_tx.send(SenderEvent::ReceiverNetworkInfo(receiver_network_info));

                    let _ = ev_tx.send(SenderEvent::HandshakeState(
                        SenderHandShakeState::VerifyingSecret,
                    ));

                    if verify_secret(&mut stream, &transfer_code)
                        .fatal(&ev_tx, |m| UiError::SecretVerificationFailed(m))
                        .is_none()
                    {
                        break;
                    }

                    let _ = ev_tx.send(SenderEvent::HandshakeState(
                        SenderHandShakeState::SecretVerified,
                    ));

                    let state = generate_key_state();

                    if send_public_key(&mut stream, &state.public_key)
                        .fatal(&ev_tx, |m| UiError::PublicKeySendFailed(m))
                        .is_none()
                    {
                        break;
                    }

                    let _ = ev_tx.send(SenderEvent::HandshakeState(
                        SenderHandShakeState::PublicKeySent,
                    ));

                    let peer_pk = match receive_public_key(&mut stream)
                        .fatal(&ev_tx, |m| UiError::PublicKeyReceiveFailed(m))
                    {
                        Some(pk) => pk,
                        None => break,
                    };

                    let _ = ev_tx.send(SenderEvent::HandshakeState(
                        SenderHandShakeState::PublicKeyReceived,
                    ));

                    let shared_secret = derive_shared_secret(state.private_key, peer_pk);

                    let _ = ev_tx.send(SenderEvent::HandshakeState(
                        SenderHandShakeState::DeriveSharedSecret,
                    ));

                    let transcript =
                        derive_transcript(state.public_key, peer_pk, &transfer_code.secret);

                    let _ = ev_tx.send(SenderEvent::HandshakeState(
                        SenderHandShakeState::DeriveTranscript,
                    ));

                    let session_keys =
                        match derive_session_keys(&shared_secret, &transcript, Mode::Sender)
                            .fatal(&ev_tx, |m| UiError::SessionKeysFailed(m))
                        {
                            Some(sk) => sk,
                            None => break,
                        };

                    let _ = ev_tx.send(SenderEvent::HandshakeState(
                        SenderHandShakeState::HandshakeCompleted,
                    ));

                    if send_file_metadata(&mut stream, file_metadata.clone())
                        .fatal(&ev_tx, |_| UiError::MetadataSendFailed)
                        .is_none()
                    {
                        break;
                    }

                    if send_hash(hash.clone(), &mut stream)
                        .fatal(&ev_tx, |_| UiError::HashSendFailed)
                        .is_none()
                    {
                        break;
                    }

                    let decision = match receive_decision(&mut stream)
                        .fatal(&ev_tx, |_| UiError::DecisionReceiveFailed)
                    {
                        Some(d) => d,
                        None => break,
                    };

                    match decision {
                        Decision::Accept => {
                            let _ = ev_tx.send(SenderEvent::TransferStarted);

                            let (final_hash, outcome) = send_file(
                                &mut file,
                                &mut stream,
                                session_keys.sender_key,
                                hash.clone(),
                                ev_tx.clone(),
                                &cancel_clone,
                                &pause_cond,
                                &pause_clone,
                            );

                            if matches!(outcome, Outcome::Completed) {
                                let _ = ev_tx.send(SenderEvent::TransferCompleted);
                                if hash.is_none() {
                                    let _ = send_hash(Some(final_hash.clone()), &mut stream);
                                    let _ = ev_tx.send(SenderEvent::FileHash(FileHash {
                                        hash: Some(final_hash),
                                    }));
                                }
                            }
                        }

                        Decision::Reject => {
                            let _ = ev_tx.send(SenderEvent::TransferCancelled);
                            break;
                        }
                    }

                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }

                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
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
        cancel,
        handle,
        pause,
    })
}

const NONCE_LEN: usize = 12;

pub fn send_nonce(stream: &mut TcpStream, nonce: Nonce) -> std::io::Result<()> {
    assert_eq!(NONCE_LEN, nonce.len());
    stream.write_all(&nonce.to_vec())?;
    stream.flush()?;
    std::io::Result::Ok(())
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
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    cond_state: &Arc<(Mutex<CondState>, Condvar)>,
) {
    let socket_addr = transfer_code.socket_addr;
    let secret = transfer_code.secret;

    let sender_info = SenderNetworkInfo {
        ip: socket_addr.ip().to_string(),
        port: socket_addr.port().to_string(),
    };

    let _ = cmd_tx.send(ReceiverState::SenderNetworkInfo(sender_info));

    let _ = cmd_tx.send(ReceiverState::Connecting);

    let mut stream =
        match TcpStream::connect(socket_addr).fatal(&cmd_tx, |_| UiError::ConnectionFailed) {
            Some(s) => {
                let _ = cmd_tx.send(ReceiverState::Connected);
                s
            }
            None => return,
        };

    let receiver_info = ReceiverNetworkInfo {
        ip: stream.local_addr().unwrap().ip().to_string(),
        port: stream.local_addr().unwrap().port().to_string(),
    };

    let _ = cmd_tx.send(ReceiverState::ReceiverNetworkInfo(receiver_info));

    info!("Connected to {socket_addr:?}");

    let _ = cmd_tx.send(ReceiverState::HandshakeState(
        ReceiveHandShakeState::Initialized,
    ));

    fatal_or_return!(
        send_secret(&mut stream, secret.clone()),
        &cmd_tx,
        UiError::SecretSendFailed
    );

    info!("Trying to receive peer's PublicKey");

    let state = generate_key_state();

    let peer_public_key =
        match receive_public_key(&mut stream).fatal(&cmd_tx, UiError::PublicKeyReceiveFailed) {
            Some(pk) => pk,
            None => return,
        };

    assert_ne!(peer_public_key.as_bytes(), state.public_key.as_bytes());

    info!("PublicKey received successfully!");

    fatal_or_return!(
        send_public_key(&mut stream, &state.public_key),
        &cmd_tx,
        UiError::PublicKeySendFailed
    );

    let _ = cmd_tx.send(ReceiverState::HandshakeState(
        ReceiveHandShakeState::PublicKeySent,
    ));

    let shared_secret = derive_shared_secret(state.private_key, peer_public_key);

    let _ = cmd_tx.send(ReceiverState::HandshakeState(
        ReceiveHandShakeState::DeriveSharedSecret,
    ));

    let transcript = derive_transcript(peer_public_key, state.public_key, &secret);

    info!("Derived Transcript");

    let _ = cmd_tx.send(ReceiverState::HandshakeState(
        ReceiveHandShakeState::DeriveTranscript,
    ));

    let session_keys = match derive_session_keys(&shared_secret, &transcript, Mode::Receiver)
        .fatal(&cmd_tx, UiError::SessionKeysFailed)
    {
        Some(sk) => sk,
        None => return,
    };

    let _ = cmd_tx.send(ReceiverState::HandshakeState(
        ReceiveHandShakeState::DeriveSessionKeys,
    ));

    let file_metadata =
        match receive_metadata(&mut stream).fatal(&cmd_tx, |_| UiError::MetadataSendFailed) {
            Some(mt) => mt,
            None => return,
        };

    let hash = match receive_hash(&mut stream) {
        Ok(hash) => hash,
        Ok(None) => {
            let _ = cmd_tx.send(ReceiverState::Error(UiError::HashReceiveFailed(Some(
                "Hash missing".into(),
            ))));
            return;
        }
        Err(e) => {
            let _ = cmd_tx.send(ReceiverState::Error(UiError::HashReceiveFailed(Some(
                e.to_string(),
            ))));
            return;
        }
    };

    let _ = cmd_tx.send(ReceiverState::FileHash(FileHash { hash }));
    let _ = cmd_tx.send(ReceiverState::FileState(file_metadata.clone()));

    let _ = ui_tx.send(ReceiverUiState::Confirming);

    let file_name = file_metadata.name;

    while let Ok(decision) = decision_rx.recv() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        match decision {
            Decision::Accept => {
                let Some(file_path) = FileDialog::new()
                    .set_title("Save File")
                    .set_file_name(file_name.clone())
                    .save_file()
                else {
                    continue;
                };

                fatal_or_return!(
                    send_decision(&mut stream, Decision::Accept),
                    &cmd_tx,
                    UiError::DecisionSendFailed
                );

                let _ = ui_tx.send(ReceiverUiState::Receiving);

                let mut file =
                    match File::create(file_path).fatal(&cmd_tx, UiError::FileWriteFailed) {
                        Some(f) => f,
                        None => return,
                    };

                if let Ok(outcome) = receive_file(
                    &mut stream,
                    session_keys.receiver_key,
                    &mut file,
                    &cmd_tx,
                    &cancel,
                    &pause,
                    &cond_state,
                ) {
                    if let Outcome::Completed = outcome {
                        let _ = cmd_tx.send(ReceiverState::RecieveCompleted);
                    }
                }
            }

            Decision::Reject => {
                let _ = send_decision(&mut stream, Decision::Reject);
                let _ = stream.shutdown(Shutdown::Both);
                break;
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
        break;
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
    state: Arc<(Mutex<CondState>, Condvar)>,
) -> Result<ReceiverTask, Error> {
    let (decision_tx, decision_rx) = std::sync::mpsc::channel();
    let pause = Arc::new(AtomicBool::new(false));
    let pause_clone = Arc::clone(&pause);

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();
    let handle = std::thread::spawn(move || {
        start_receiver(
            transfer_code,
            rec_tx,
            decision_rx,
            ui_tx,
            cancel_clone,
            pause_clone,
            &state,
        )
    });

    Ok(ReceiverTask {
        handle: handle,
        decision_tx: decision_tx,
        cancel: cancel,
        pause: pause,
    })
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

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
        let sender_shared_secret =
            derive_shared_secret(sender_state.private_key, receiver_state.public_key);
        let receiver_shared_secret =
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
