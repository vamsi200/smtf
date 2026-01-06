#![allow(dead_code)]
#![allow(unused)]

use anyhow::{Error, Result};
use chacha20poly1305::Nonce;
use rand::RngCore;
use rand::{rngs::OsRng, TryRngCore};
use sha2::{Digest, Sha256};
use std::env::Args;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{
    Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::os::unix::process;
use std::path::Path;
use std::process::exit;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroize;

use crate::crypto::{self, derive_session_keys, encrypt_data, Mode};

pub struct HandshakeState {
    public_key: PublicKey,
    private_key: EphemeralSecret,
}

#[derive(Debug)]
pub struct TransferCode {
    socket_addr: SocketAddr,
    pub secret: Vec<u8>,
}

type RawTransferCode = String;
type HumanReadableTransferCode = String;

// Sender
pub fn generate_key_state() -> HandshakeState {
    let sender_private_key = EphemeralSecret::random();
    let sender_public_key = PublicKey::from(&sender_private_key);

    HandshakeState {
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
pub fn generate_receiver_key_state() -> HandshakeState {
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
pub fn decode(encoded_data: &HumanReadableTransferCode) -> Result<TransferCode, Error> {
    let raw = parse_transfer_code(encoded_data);
    let mut s = base32::decode(base32::Alphabet::Crockford, &raw).unwrap();
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

use crate::transfer::{self, receive_file, send_file};
use rfd::FileDialog;

// Sender
pub fn sender(socket_addr: SocketAddr, transfer_code: TransferCode) -> Result<(), Error> {
    let mut buf = [0u8; 17];
    let file_path = FileDialog::new().set_directory(".").pick_file().unwrap();

    let mut file = File::open(file_path.clone())?;
    println!("File Selected - {file_path:?}");

    match TcpListener::bind(socket_addr) {
        Ok(listener) => {
            let local_addr = listener.local_addr()?;
            println!("Listener Started - {}", local_addr);
            if let Ok((mut stream, s)) = listener.accept() {
                println!("Someone connected - {s:?}");
                if verify_secret(&mut stream, &transfer_code)? {
                    let state = generate_key_state();
                    send_public_key(&mut stream, &state.public_key)?;
                    println!("[INFO] PublicKey sent successfully!");

                    if let Ok(peer_public_key) = receive_public_key(&mut stream) {
                        println!("[INFO] PublicKey received successfully!");
                        let shared_secret =
                            derive_shared_secret(state.private_key, peer_public_key);
                        let transcript = derive_transcript(
                            state.public_key,
                            peer_public_key,
                            &transfer_code.secret,
                        );

                        let session_keys =
                            derive_session_keys(&shared_secret, &transcript, Mode::Sender)?;

                        send_file(&mut file, &mut stream, session_keys.sender_key);
                    }
                } else {
                    stream.shutdown(std::net::Shutdown::Both);
                    exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

pub fn send_nonce(stream: &mut TcpStream, nonce: Nonce) -> Result<(), Error> {
    let nonce_len = nonce.len() as u16;
    stream.write_all(&nonce_len.to_be_bytes())?;
    stream.write_all(&nonce.to_vec())?;
    stream.flush()?;

    Ok(())
}

pub fn receive_nonce(stream: &mut TcpStream) -> Result<Nonce, Error> {
    let mut nonce_buf_len = [0u8; 2];
    stream.read_exact(&mut nonce_buf_len)?;

    let len = u16::from_be_bytes(nonce_buf_len) as usize;

    let mut buf = vec![0u8; len];

    stream.read_exact(&mut buf)?;

    Ok(Nonce::from_slice(&buf).to_owned())
}

pub fn send_public_key(stream: &mut TcpStream, public_key: &PublicKey) -> Result<(), Error> {
    let public_key = public_key.as_bytes();

    let len = public_key.len() as u16;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(public_key)?;
    stream.flush()?;

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
        println!("Yipeee!");
        true
    };
    Ok(verify)
}

// Receiver
pub fn receiver(transfer_code: TransferCode) -> Result<(), Error> {
    let socket_addr = transfer_code.socket_addr;
    let secret = transfer_code.secret;

    if let Ok(mut stream) = TcpStream::connect(socket_addr) {
        send_secret(&mut stream, secret.clone())?;
        println!("[INFO] Trying to get Sender's PublicKey");

        let state = generate_key_state();
        let peer_public_key = receive_public_key(&mut stream)?;
        assert_ne!(peer_public_key.as_bytes(), state.public_key.as_bytes());

        println!("[INFO] PublicKey received successfully!");

        if let Ok(_) = send_public_key(&mut stream, &state.public_key) {
            let mut file = File::create("./write.txt")?;
            println!("[INFO] PublicKey sent successfully!");
            let shared_secret = derive_shared_secret(state.private_key, peer_public_key);

            let transcript = derive_transcript(peer_public_key, state.public_key, &secret);
            let session_keys = derive_session_keys(&shared_secret, &transcript, Mode::Receiver)?;

            receive_file(&mut stream, session_keys.receiver_key, &mut file);
        }
    } else {
        println!("Couldn't connect bro..");
    }

    Ok(())
}

pub fn test(socket: SocketAddr, human_readable_code: String) -> Result<(), Error> {
    let mut receive = false;
    let mut arguments = std::env::args().skip(1);
    let mut code = String::new();

    while let Some(args) = arguments.next() {
        match args.as_str() {
            "receive" => receive = true,
            "-code" => code = arguments.next().and_then(|x| x.parse().ok()).unwrap(),
            _ => {}
        }
    }

    let transfer_code = decode(&human_readable_code)?;

    if receive {
        let transfer_code = decode(&code)?;
        receiver(transfer_code)?;
    } else {
        println!("Code: {human_readable_code}");
        sender(socket, transfer_code)?;
    }

    Ok(())
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
