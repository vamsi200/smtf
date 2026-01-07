#![allow(unused)]

use std::net::SocketAddr;

#[derive(Debug)]
pub struct FileMetadata {
    pub name: String,
    pub size: String,
    pub file_type: String,
    pub path: String,
    pub hash: String,
}

pub struct Networkdata {
    pub address: String,
}

pub struct ProgressData {
    pub speed: String,
    pub eta: String,
}

pub enum ProgressState {
    ProgressInfo(ProgressData),
    Error(String),
}

#[derive(Debug)]
pub enum FileState {
    FileSelected(FileMetadata),
    Error(String),
}

pub struct DestinationData {
    pub path: String,
    pub free_space: String,
    pub need_space: String,
}

pub enum DestinationState {
    DestionationInfo(DestinationData),
    SufficientSpace(bool),
    Error(String),
}

pub enum SenderState {
    ListenerStarted(SocketAddr),
    SecretValue(String),
    PeerConnected(SocketAddr),
    VerifyingSecret,
    SecretVerified,
    PublicKeySent,
    PublicKeyReceived,
    DeriveSharedSecret,
    DeriveTranscript,
    DeriveSessionKeys,
    FileState(FileState),
    TransferStarted,
    TransferCompleted,
    Error(String),
}

pub enum RecieverState {
    PeerConnected(SocketAddr),
    SendSecret,
    SecretSent,
    SecretVerified,
    PublicKeySent,
    PublicKeyReceived,
    DeriveSharedSecret,
    DeriveTranscript,
    DeriveSessionKeys,
    FileState(FileState),
    RecieveStarted,
    RecieveCompleted,
    Error(String),
}
