#![allow(unused)]
use anyhow::{Error, Result};
use std::{
    fs::File,
    io::{Read, Write},
    net::TcpStream,
};

use crate::{
    crypto::{decrypt_data, encrypt_data},
    handshake::{receive_nonce, send_nonce},
};

pub fn send_file(file: &mut File, stream: &mut TcpStream, sender_key: [u8; 32]) {
    let mut buf = [0u8; 64];

    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            let eof_nonce = [0u8; 12];
            send_nonce(stream, eof_nonce.into()).unwrap();
            stream.write_all(&0u16.to_be_bytes()).unwrap();
            break;
        }

        let (encrypted_chunks, nonce) = encrypt_data(sender_key, &buf[..n].to_vec());
        send_nonce(stream, nonce).unwrap();
        stream.write_all(&(encrypted_chunks.len() as u16).to_be_bytes());
        stream.write_all(&encrypted_chunks).unwrap();
    }
}

pub fn receive_file(stream: &mut TcpStream, receiver_key: [u8; 32]) {
    let mut file = File::create("./write.txt").unwrap();
    loop {
        let nonce = receive_nonce(stream).unwrap();
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).unwrap();
        let buf_len = u16::from_be_bytes(len) as usize;

        if buf_len == 0 {
            break;
        }

        let mut buf = vec![0u8; buf_len];
        stream.read_exact(&mut buf).unwrap();

        let decrypted = decrypt_data(buf, nonce, receiver_key);
        file.write_all(&decrypted).unwrap();
    }
}
