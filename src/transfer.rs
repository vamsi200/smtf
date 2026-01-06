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
    let mut buf = [0u8; 512 * 1024];
    let mut hasher = blake3::Hasher::new();

    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            let eof_nonce = [0u8; 12];
            send_nonce(stream, eof_nonce.into()).unwrap();
            stream.write_all(&0u32.to_be_bytes()).unwrap();
            stream.write_all(&0u32.to_be_bytes()).unwrap();
            break;
        }

        let plain_text_len = n as u32;
        let (encrypted_chunks, nonce) = encrypt_data(sender_key, &buf[..n]);
        hasher.update(&buf);

        send_nonce(stream, nonce).unwrap();

        stream.write_all(&plain_text_len.to_be_bytes());
        stream.write_all(&(encrypted_chunks.len() as u32).to_be_bytes());
        stream.write_all(&encrypted_chunks).unwrap();
    }
    println!("Hash - {:?}", hasher.finalize());
}

pub fn receive_file(stream: &mut TcpStream, receiver_key: [u8; 32], file: &mut File) {
    loop {
        let nonce = receive_nonce(stream).unwrap();
        let mut encrypted_chunk_len = [0u8; 4];
        let mut plain_text_len = [0u8; 4];

        stream.read_exact(&mut plain_text_len).unwrap();
        stream.read_exact(&mut encrypted_chunk_len).unwrap();

        let plain_text_buf_len = u32::from_be_bytes(plain_text_len) as usize;
        let encrypted_buf_len = u32::from_be_bytes(encrypted_chunk_len) as usize;

        if encrypted_buf_len == 0 {
            break;
        }

        let mut buf = vec![0u8; encrypted_buf_len];
        stream.read_exact(&mut buf).unwrap();

        let decrypted = decrypt_data(buf, nonce, receiver_key);
        assert_eq!(decrypted.len(), plain_text_buf_len);
        file.write_all(&decrypted).unwrap();
    }
}
