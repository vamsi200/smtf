use anyhow::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::SharedSecret;

#[derive(Clone, Debug)]
pub struct SessionKeys {
    pub sender_key: [u8; 32],
    pub receiver_key: [u8; 32],
}

pub enum Mode {
    Sender,
    Receiver,
}

pub fn derive_session_keys(
    shared: &SharedSecret,
    transcript: &Vec<u8>,
    role: Mode,
) -> Result<SessionKeys, Error> {
    let hk = Hkdf::<Sha256>::new(Some(&transcript), shared.as_bytes());
    let mut tx_key = [0u8; 32];
    let mut rx_key = [0u8; 32];

    hk.expand(b"sender->receiver", &mut tx_key)
        .expect("Failed to expand the sender key");
    hk.expand(b"receiver->sender", &mut rx_key)
        .expect("Failed to expand the receiver key");

    Ok(match role {
        Mode::Sender => SessionKeys {
            sender_key: tx_key,
            receiver_key: rx_key,
        },
        Mode::Receiver => SessionKeys {
            sender_key: rx_key,
            receiver_key: tx_key,
        },
    })
}

pub fn encrypt_data(sender_key: [u8; 32], data: &[u8]) -> (Vec<u8>, Nonce) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sender_key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let cipher_text = cipher.encrypt(&nonce, data).unwrap();

    (cipher_text, nonce)
}

pub fn decrypt_data(cipher_text: Vec<u8>, nonce: Nonce, receive_key: [u8; 32]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&receive_key));
    cipher
        .decrypt(&nonce, &*cipher_text)
        .expect("Failed to decrypt data")
}
