#![allow(unused)]

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{atomic::AtomicBool, mpsc, Arc, Condvar, Mutex},
    thread::JoinHandle,
};

use blake3::Hash;

use crate::handshake::{Decision, TransferCode};

#[derive(Debug, Clone, PartialEq)]
pub struct FileMetadata {
    pub name: String,
    pub size: String,
    pub raw_bytes: u64,
    pub file_type: String,
    pub path: String,
    pub modified_date: String,
}

#[derive(Clone, Debug)]
pub struct FileHash {
    pub hash: Option<Hash>,
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

#[derive(Clone, Debug)]
pub struct HandshakeData {
    pub cwd: PathBuf,
    pub socket_addr: SocketAddr,
    pub secrte_code: String, // sharing code to the reciever
    pub transfer_code: TransferCode,
    pub file_path: PathBuf,
}

pub struct Task {
    pub cancel: Arc<AtomicBool>,
    pub handle: JoinHandle<()>,
    pub pause: Arc<AtomicBool>,
}

pub enum BackendState {
    Idle,
    Sending(Task),
    Receving(ReceiverTask),
}

pub struct ReceiverTask {
    pub handle: JoinHandle<()>,
    pub cancel: Arc<AtomicBool>,
    pub decision_tx: std::sync::mpsc::Sender<Decision>,
    pub pause: Arc<AtomicBool>,
}

pub enum Command {
    StartSender { file_path: PathBuf },
    StartReciver { code: String },
    Cancel,
    Close,
    Decision(Decision),
    Pause,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct TransferProgress {
    pub total: u64,
    pub sent: usize,
}

impl TransferProgress {
    pub fn fraction(&self) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            self.sent as f32 / self.total as f32
        }
    }

    pub fn percent(&self) -> f32 {
        self.fraction() * 100.0
    }
}

pub enum SenderEvent {
    ListenerStarted(SocketAddr),
    HandshakeDerived(HandshakeData),
    HandshakeState(SenderHandShakeState),
    FileData(FileMetadata),
    Trasnfer(TransferProgress),
    FileHash(FileHash),
    SecretValue(String),
    PeerConnected(SocketAddr),
    TransferStarted,
    TransferCompleted,
    Error(UiError),
}

#[derive(Debug, Clone)]
pub enum UiError {
    PublicKeySendFailed(Option<String>),
    PublicKeyReceiveFailed(Option<String>),
    SecretSendFailed(Option<String>),
    SessionKeysFailed(Option<String>),
    SecretVerificationFailed(Option<String>),
    HandshakeFailed(Option<String>),
    NonceSendFailed(Option<String>),
    TransferFailed(Option<String>),
    HashReceiveFailed(Option<String>),
    DecisionSendFailed(Option<String>),
    ConnectionLost(Option<String>),
    NonceReceiveFailed(Option<String>),
    ChunkLengthReceiveFailed(Option<String>),
    ChunkReceiveFailed(Option<String>),
    FileWriteFailed(Option<String>),
    DecodeFailed(Option<String>),
    ConnectionFailed,
    MetadataSendFailed,
    HashSendFailed,
    DecisionReceiveFailed,
    PermissionDenied,
    TransferCancelled,
    UnexpectedEof,

    Unknown(String),
}

impl UiError {
    pub fn title(&self) -> &'static str {
        match self {
            UiError::PublicKeySendFailed(_) => "Public key send failed",
            UiError::PublicKeyReceiveFailed(_) => "Public key receive failed",
            UiError::SecretSendFailed(_) => "Secret send failed",
            UiError::SessionKeysFailed(_) => "Session key derivation failed",
            UiError::SecretVerificationFailed(_) => "Secret verification failed",
            UiError::HandshakeFailed(_) => "Handshake failed",

            UiError::NonceSendFailed(_) => "Nonce send failed",
            UiError::NonceReceiveFailed(_) => "Nonce receive failed",
            UiError::ChunkLengthReceiveFailed(_) => "Failed to receive chunk length",
            UiError::ChunkReceiveFailed(_) => "Failed to receive encrypted chunk",
            UiError::TransferFailed(_) => "File transfer failed",
            UiError::FileWriteFailed(_) => "Failed to write file",

            UiError::HashReceiveFailed(_) => "Failed to receive hash",
            UiError::HashSendFailed => "Failed to send hash",
            UiError::DecisionSendFailed(_) => "Failed to send decision",
            UiError::DecisionReceiveFailed => "Failed to receive decision",
            UiError::MetadataSendFailed => "Failed to send metadata",

            UiError::ConnectionLost(_) => "Connection lost",
            UiError::ConnectionFailed => "Connection failed",
            UiError::PermissionDenied => "Permission denied",
            UiError::TransferCancelled => "Transfer cancelled",
            UiError::UnexpectedEof => "Unexpected end of stream",
            UiError::DecodeFailed(_) => "Code Decode Failed",

            UiError::Unknown(_) => "Unknown error",
        }
    }

    pub fn details(&self) -> Option<&str> {
        match self {
            UiError::PublicKeySendFailed(Some(msg))
            | UiError::PublicKeyReceiveFailed(Some(msg))
            | UiError::SecretSendFailed(Some(msg))
            | UiError::SessionKeysFailed(Some(msg))
            | UiError::SecretVerificationFailed(Some(msg))
            | UiError::HandshakeFailed(Some(msg))
            | UiError::NonceSendFailed(Some(msg))
            | UiError::NonceReceiveFailed(Some(msg))
            | UiError::TransferFailed(Some(msg))
            | UiError::HashReceiveFailed(Some(msg))
            | UiError::DecisionSendFailed(Some(msg))
            | UiError::ConnectionLost(Some(msg))
            | UiError::ChunkLengthReceiveFailed(Some(msg))
            | UiError::ChunkReceiveFailed(Some(msg))
            | UiError::FileWriteFailed(Some(msg)) => Some(msg),

            UiError::DecodeFailed(Some(msg)) => Some(msg),
            UiError::Unknown(msg) => Some(msg),

            _ => None,
        }
    }
}

// maybe add cancel later
#[derive(PartialEq, PartialOrd, Debug)]
pub enum ReceiveHandShakeState {
    Initialized,
    PublicKeySent,
    PublicKeyReceived,
    DeriveSharedSecret,
    DeriveTranscript,
    DeriveSessionKeys,
    HandshakeCompleted,
}

#[derive(PartialEq, PartialOrd, Debug)]
pub enum SenderHandShakeState {
    Initialized,
    SecretDerived,
    VerifyingSecret,
    SecretVerified,
    PublicKeySent,
    PublicKeyReceived,
    DeriveSharedSecret,
    DeriveTranscript,
    DeriveSessionKeys,
    HandshakeCompleted,
}

pub enum ReceiverState {
    SecretValue(String),
    HandshakeState(ReceiveHandShakeState),
    ReceivedBytes(usize),
    FilePath(PathBuf),
    FileState(FileMetadata),
    FileHash(FileHash),
    RecieveCompleted,
    Error(UiError),
}

pub enum ReceiverUiState {
    Idle,
    Confirming,
    Receiving,
    Completed,
}
