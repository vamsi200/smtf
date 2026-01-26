# SMTF – Send Me The File

SMTF is a secure, peer-to-peer file transfer system over TCP designed with minimal trust assumptions and no central servers. It emphasizes direct connectivity, modern cryptography, and robust protocol design for safe and reliable file transfers between peers.

> Note: This Tool expects the sender to be publicly available.

## Features

### 1. Architecture

Pure peer-to-peer file transfer over TCP.

- No central servers
- No brokers or relays
- Direct connectivity between peers
- Minimal trust assumptions


### 2. Session Security

Ephemeral secrets are generated per transfer session.

- Secure OS randomness
- No long-term shared secrets
- Reduced replay and key-compromise risk


### 3. Data Protection

End-to-end encryption using ChaCha20-Poly1305.

Encryption is performed in fixed-size chunks to enable:

- Large file support
- Partial transfer recovery
- Per-chunk integrity and authentication

### 4. Key Exchange and Forward Secrecy

Per-session encryption keys are derived using:

- X25519 Diffie-Hellman key exchange
- HKDF-based key derivation

This ensures:

- Forward secrecy
- Cryptographic isolation between transfers
- No key reuse across sessions



## Requirements

- Git
- Rust (rustc and cargo)
- TCP connectivity between peers


## Installation and Build

### Windows

1) Install Git Bash

   Download and install Git for Windows (includes Git Bash) - https://git-scm.com/download/win

2) Install Rust (rustc and cargo)

   Install Rust using rustup - https://www.rust-lang.org/tools/install
   
   Ensure cargo is added to your PATH during installation.

3) Clone the repository

- Open Git Bash and run:
   
  ```bash
  git clone https://github.com/vamsi200/smtf/
  cd smtf
  ```

- Build the project

  ```bash
  cargo build --release
  ```

- The compiled binary will be available in:

  ```bash
  target/release/
  ```

### Linux

1. Install Git

- Use your distribution’s package manager, for example:

  ```bash
  sudo pacman -S git        # Arch
  sudo apt install git      # Debian/Ubuntu
  sudo dnf install git      # Fedora
  ```

2. Install Rust (rustc and cargo)

- Install Rust using rustup:

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- Reload your shell:
   
  ```bash
  source ~/.cargo/env
  ```

- Clone the repository

  ```bash
  git clone https://github.com/vamsi200/smtf/
  cd smtf
  ```

- Build the project

  ```bash
  cargo build --release
  ```

- The compiled binary will be available in:

  ```bash
  target/release/
  ```


## Security Notes

- All cryptographic material is ephemeral and scoped to a single session.
- No plaintext file data is transmitted over the network.
- Each transfer is isolated to prevent key reuse or cross-session compromise.


## Disclaimer

This project is intended for educational and experimental purposes. It has not been independently audited. Use at your own risk.
