#![allow(dead_code)]
#![allow(unused)]

use anyhow::{Error, Result};
use rand::RngCore;
use rand::{rngs::OsRng, TryRngCore};
use std::net::{
    Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::str::FromStr;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub struct HandshakeState {
    public_key: PublicKey,
    shared_secret: SharedSecret,
    key_pair: EphemeralSecret,
}

#[derive(Debug)]
pub struct TransferCode {
    socket_addr: SocketAddr,
    secret: Vec<u8>,
}

type RawTransferCode = String;
type HumanReadableTransferCode = String;

// Sender
pub fn generate_sender_key_state() -> HandshakeState {
    todo!()
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

pub fn parse_transfer_code(transfer_code: String) -> RawTransferCode {
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
pub fn decode(encoded_data: HumanReadableTransferCode) -> Result<TransferCode, Error> {
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

// Sender
pub fn bind_and_listen() -> Result<Connection, Error> {
    let udp_sock = UdpSocket::bind("[::]:0")?;
    udp_sock.connect("[2606:4700:4700::1111]:80")?;
    let socket_addr = udp_sock.local_addr()?;

    let connection = match TcpListener::bind(socket_addr) {
        Ok(listener) => {
            let local_addr = listener.local_addr()?;
            println!("Listener Started - {}", local_addr);
            let conn = listener.accept()?;
            conn
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    Ok(connection)
}
// Receiver
pub fn connect_to_sender(transfer_code: TransferCode) -> Result<(), Error> {
    let socket_addr = transfer_code.socket_addr;
    let secret = transfer_code.secret;

    if let Ok(s) = TcpStream::connect(socket_addr) {
        println!("Connected!");
        // Send the secret to the sender and the sender checks and confirms it, then we proceed
        // with the key generation from both parties
    } else {
        println!("Bruh..");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

    fn test_socket_addr() -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 4242, 0, 0))
    }

    #[test]
    fn test_human_readable_roundtrip() {
        let raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        let human = gen_human_readable_transfer_code(raw);
        let parsed = parse_transfer_code(human);
        assert_eq!(raw, parsed);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let socket = test_socket_addr();
        let encoded = encode(socket).expect("encode failed");

        let raw = parse_transfer_code(encoded.clone());
        let decoded = decode(raw).expect("decode failed");

        assert_eq!(decoded.socket_addr, socket);
        assert_eq!(decoded.secret.len(), 16);
    }

    #[test]
    fn test_secret_is_random() {
        let socket = test_socket_addr();

        let code1 = encode(socket).unwrap();
        let code2 = encode(socket).unwrap();

        let raw1 = parse_transfer_code(code1);
        let raw2 = parse_transfer_code(code2);

        let d1 = decode(raw1).unwrap();
        let d2 = decode(raw2).unwrap();

        assert_ne!(d1.secret, d2.secret, "Secrets should be random");
    }

    #[test]
    fn test_transfer_code_contains_valid_socket() {
        let socket = test_socket_addr();
        let encoded = encode(socket).unwrap();

        let raw = parse_transfer_code(encoded);
        let decoded = decode(raw).unwrap();

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

        let raw = parse_transfer_code(encoded);
        let decoded_bytes = base32::decode(base32::Alphabet::Crockford, &raw).unwrap();

        assert!(decoded_bytes.len() > 16);
    }
}
