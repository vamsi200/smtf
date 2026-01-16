#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use anyhow::{Error, Ok};
use arboard::Clipboard;
use eframe::{Frame, NativeOptions};
use egui::{Context, FontData, FontDefinitions, Grid, Stroke};
use log::info;
use rfd::FileDialog;
use smtf::{
    handshake::{self, *},
    helper::{self, get_file_size, get_socket_addr},
    state::{
        self, BackendState, Command, FileHash, FileMetadata, HandshakeData, ReceiverState,
        ReceiverUiState, SenderEvent, UiError,
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
use std::{
    sync::Condvar,
    time::{Duration, Instant},
};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

fn main() -> Result<(), Error> {
    env_logger::init();
    let (ev_tx, ev_rx) = mpsc::channel::<SenderEvent>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>();
    let (rec_tx, rec_rx) = mpsc::channel::<ReceiverState>();
    let (ui_tx, ui_rx) = mpsc::channel::<ReceiverUiState>();

    let cond_var = Arc::new((Mutex::new(false), Condvar::new()));
    let cond_var_clone = Arc::clone(&cond_var);

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
        ui_error: None,
        sender_network_info: None,
        receiver_network_info: None,
    };

    std::thread::spawn(move || {
        entry_point(ev_tx, cmd_rx, rec_tx, ui_tx, cond_var_clone)
            .expect("entry is closed unexpectedly");
    });

    let clipboard = Clipboard::new().unwrap();
    ui::AppState::app(app_state, ev_rx, cmd_tx, rec_rx, ui_rx, cond_var, clipboard)
        .expect("Failed to start gui");

    // transfer_code.secret.zeroize();
    Ok(())
}

pub fn entry_point(
    ev_tx: mpsc::Sender<SenderEvent>,
    cmd_rx: mpsc::Receiver<Command>,
    rec_tx: mpsc::Sender<ReceiverState>,
    ui_tx: mpsc::Sender<ReceiverUiState>,
    cond_var: Arc<(Mutex<bool>, Condvar)>,
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
                    let new_task = sender(ev_tx.clone(), file_path, cond_var.clone())
                        .expect("Failed to get sender task");
                    state = BackendState::Sending(new_task);
                }

                Command::StartReciver { code } => {
                    match decode(&code) {
                        Some(tc) => {
                            let new_task =
                                receiver(tc, rec_tx.clone(), ui_tx.clone(), cond_var.clone())?;
                            state = BackendState::Receving(new_task);
                        }
                        None => {
                            rec_tx.send(ReceiverState::Error(
                                UiError::SecretVerificationFailed(Some(
                                    "Invalid Secret!".to_string(),
                                )),
                            ))?;
                            continue;
                        }
                    };
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

                Command::Pause => {
                    if let BackendState::Sending(task) = state {
                        task.pause.store(true, Ordering::Relaxed);
                        let _ = task.handle.join();
                        state = BackendState::Idle;
                        info!("Called pause on sender");
                    }
                    if let BackendState::Receving(task) = state {
                        task.pause.store(true, Ordering::Relaxed);
                        let _ = task.handle.join();
                        state = BackendState::Idle;
                        info!("Called pause on receiver");
                    }
                }

                _ => {}
            },
            Err(err) => {
                eprintln!("Error: {err}");
                break Ok(());
            }
        }
    }
}
