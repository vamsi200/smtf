#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use anyhow::{Error, Ok};
use eframe::{Frame, NativeOptions};
use egui::{Context, FontData, FontDefinitions, Grid, Stroke};
use log::info;
use rfd::FileDialog;
use smtf::{
    handshake::{self, *},
    helper::{self, get_file_size, get_socket_addr},
    state::{
        self, BackendState, Command, FileHash, FileMetadata, HandshakeData, ReceiverState,
        ReceiverUiState, SenderEvent,
    },
    transfer::send_file,
    ui::{self, AppState},
};
use std::{
    env::{self, Args},
    fs::File,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
        Arc, Mutex,
    },
};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use std::time::{Duration, Instant};

fn main() -> Result<(), Error> {
    env_logger::init();
    let (ev_tx, ev_rx) = mpsc::channel::<SenderEvent>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>();
    let (rec_tx, rec_rx) = mpsc::channel::<ReceiverState>();
    let (ui_tx, ui_rx) = mpsc::channel::<ReceiverUiState>();

    let app_state = AppState {
        handshake_state: None,
        is_sent: false,
        is_sending: false,
        file_metadata: None,
        file_hash: FileHash { hash: None },
        handshake_data: None,
        completion_status: None,
        ui_state: None,
        transfer_progress: None,
        received_handshake_state: None,
    };

    std::thread::spawn(move || {
        entry_point(ev_tx, cmd_rx, rec_tx, ui_tx).expect("entry is closed unexpectedly");
    });

    ui::AppState::app(app_state, ev_rx, cmd_tx, rec_rx, ui_rx).expect("Failed to start gui");

    // transfer_code.secret.zeroize();
    Ok(())
}

pub fn entry_point(
    ev_tx: mpsc::Sender<SenderEvent>,
    cmd_rx: mpsc::Receiver<Command>,
    rec_tx: mpsc::Sender<ReceiverState>,
    ui_tx: mpsc::Sender<ReceiverUiState>,
) -> Result<(), Error> {
    let mut state = BackendState::Idle;

    loop {
        match cmd_rx.recv() {
            std::result::Result::Ok(cmd) => match cmd {
                Command::StartSender { file_path } => {
                    if let BackendState::Sending(task) = state {
                        task.cancel.store(true, Ordering::Relaxed);
                        task.handle
                            .join()
                            .expect("failed to complete the sender task");
                    }
                    let new_task =
                        sender(ev_tx.clone(), file_path).expect("Failed to get sender task");
                    state = BackendState::Sending(new_task);
                }
                Command::StartReciver { code } => {
                    if let BackendState::Sending(task) = state {
                        task.cancel.store(true, Ordering::Relaxed);
                        task.handle
                            .join()
                            .expect("Failed to complete the reciever task");
                    }
                    let transfer_code = decode(&code)?;
                    let new_task = receiver(transfer_code, rec_tx.clone(), ui_tx.clone())?;
                    state = BackendState::Receving(new_task);
                }
                Command::Decision(decision) => {
                    if let BackendState::Receving(task) = &state {
                        let _ = task.decision_tx.send(decision);
                    }
                }
                Command::Cancel => {
                    if let BackendState::Sending(task) = state {
                        task.cancel.store(true, Ordering::Relaxed);
                        let _ = task.handle.join();
                        state = BackendState::Idle;
                        info!("Called cancel on sender");
                    }
                    if let BackendState::Receving(task) = state {
                        task.cancel.store(true, Ordering::Relaxed);
                        let _ = task.handle.join();
                        state = BackendState::Idle;
                        info!("Called cancel on receiver");
                    }
                }
                _ => {}
            },
            Err(err) => {
                info!("Receive Error..");
                return Err(anyhow::Error::new(err));
            }
        }
    }
}
