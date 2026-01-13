#![allow(unused)]

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
    thread::JoinHandle,
};

use blake3::Hash;

use crate::handshake::{Decision, TransferCode};

#[derive(Debug, Clone, PartialEq)]
pub struct FileMetadata {
    pub name: String,
    pub size: String,
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HandShakeState {
    Initialzed,
    Secret,
    Handshake,
    Sending,
    Completed,
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
}

pub enum BackendState {
    Idle,
    Sending(Task),
    Receving(ReceiverTask),
}

pub struct ReceiverTask {
    pub handle: JoinHandle<()>,
    pub decision_tx: std::sync::mpsc::Sender<Decision>,
}

pub enum Command {
    StartSender { file_path: PathBuf },
    StartReciver { code: String },
    Cancel,
    Close,
    Decision(Decision),
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
    HandshakeState(HandShakeState),
    FileData(FileMetadata),
    Trasnfer(TransferProgress),
    FileHash(FileHash),
    SecretValue(String),
    PeerConnected(SocketAddr),
    VerifyingSecret,
    SecretVerified,
    PublicKeySent,
    PublicKeyReceived,
    DeriveSharedSecret,
    DeriveTranscript,
    DeriveSessionKeys,
    TransferStarted,
    TransferCompleted,
    Error(String),
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

pub enum ReceiverState {
    SecretValue(String),
    HandshakeState(ReceiveHandShakeState),
    ReceivedBytes(usize),
    SendSecret,
    SecretVerified,
    PublicKeySent,
    PublicKeyReceived,
    DeriveSharedSecret,
    DeriveTranscript,
    DeriveSessionKeys,
    FilePath(PathBuf),
    FileState(FileMetadata),
    FileHash(FileHash),
    RecieveStarted,
    RecieveCompleted,
    Error(String),
}

pub enum ReceiverUiState {
    Idle,
    Confirming,
    Receiving,
    Completed,
}
