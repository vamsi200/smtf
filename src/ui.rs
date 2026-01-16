#![allow(unused)]
use arboard::Clipboard;
use blake3::Hash;
use eframe::{NativeOptions, Renderer};
use egui::{epaint::FontsView, *};
use log::info;
use rfd::FileDialog;
use std::{
    net::TcpListener,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Condvar, Mutex,
    },
    time::Instant,
};

use crate::{
    handshake::{decode, encode, sender, Decision},
    helper::get_socket_addr,
    state::{
        Command, FileHash, FileMetadata, HandshakeData, ReceiveHandShakeState, ReceiverNetworkInfo,
        ReceiverUiState, SenderEvent, SenderHandShakeState, SenderNetworkInfo, TransferProgress,
        UiError,
    },
    transfer::Outcome,
};

pub struct AppState {
    pub file_metadata: Option<FileMetadata>,
    pub file_hash: FileHash,
    pub handshake_data: Option<HandshakeData>,
    pub handshake_state: Option<SenderHandShakeState>,
    pub completion_status: Option<ReceiverState>,
    pub is_sending: bool,
    pub is_sent: bool,
    pub ui_state: Option<ReceiverUiState>,
    pub transfer_progress: Option<TransferProgress>,
    pub received_handshake_state: Option<ReceiveHandShakeState>,
    pub ui_error: Option<UiError>,
    pub sender_network_info: Option<SenderNetworkInfo>,
    pub receiver_network_info: Option<ReceiverNetworkInfo>,
}

impl AppState {
    pub fn app(
        mut self,
        ev_rx: Receiver<SenderEvent>,
        cmd_tx: Sender<Command>,
        rec_rx: Receiver<ReceiverState>,
        ui_rx: Receiver<ReceiverUiState>,
        cond_var: Arc<(Mutex<bool>, Condvar)>,
        mut clipboard: Clipboard,
    ) -> eframe::Result<()> {
        let options = NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1280.0, 800.0])
                .with_min_inner_size([900.0, 600.0]),
            renderer: Renderer::Wgpu,
            ..Default::default()
        };

        let mut mode = Mode::Idle;
        let mut receiver_secret = String::new();
        let mut cancel_confirm = CancelConfirm::default();

        eframe::run_simple_native("SMTF", options, move |ctx, _frame| {
            ctx.request_repaint();

            egui::CentralPanel::default()
                .frame(egui::Frame {
                    fill: egui::Color32::from_rgb(12, 12, 16),
                    ..Default::default()
                })
                .show(ctx, |ui| match mode {
                    Mode::Idle => {
                        self.file_metadata = None;
                        self.handshake_data = None;
                        self.handshake_state = None;
                        self.completion_status = None;
                        self.is_sending = false;
                        self.is_sent = false;
                        self.ui_state = None;
                        self.transfer_progress = None;
                        self.received_handshake_state = None;
                        self.sender_network_info = None;
                        self.receiver_network_info = None;

                        ui.vertical_centered(|ui| {
                            ui.add_space(50.0);
                            ui.label(
                                egui::RichText::new("SMTF")
                                    .size(48.0)
                                    .color(egui::Color32::from_rgb(220, 220, 240))
                                    .strong(),
                            );
                            ui.add_space(8.0);
                            ui.label(
                                egui::RichText::new("Send Me The File")
                                    .size(14.0)
                                    .color(egui::Color32::from_rgb(120, 120, 140)),
                            );

                            ui.add_space(40.0);

                            ui.add_space(30.0);

                            mode_selection_card(ui, &mut mode, &cmd_tx);
                        });
                    }

                    Mode::Send => {
                        let b = top_bar(
                            ui,
                            egui::Color32::from_rgb(100, 180, 255),
                            &mut mode,
                            &cmd_tx,
                        );

                        if b {
                            cancel_confirm.open = true;
                        }

                        cancel_transfer_popup(ctx, &mut cancel_confirm, true, &mut mode, || {
                            cmd_tx.send(Command::Cancel);
                        });

                        ui.vertical_centered(|ui| {
                            ui.add_space(30.0);

                            while let Ok(ev) = ev_rx.try_recv() {
                                match ev {
                                    SenderEvent::FileData(meta) => {
                                        self.file_metadata = Some(meta);
                                    }
                                    SenderEvent::FileHash(hash) => self.file_hash = hash,
                                    SenderEvent::HandshakeDerived(hd) => {
                                        self.handshake_data = Some(hd)
                                    }
                                    SenderEvent::HandshakeState(hs) => {
                                        self.handshake_state = Some(hs)
                                    }
                                    SenderEvent::Trasnfer(tp) => self.transfer_progress = Some(tp),
                                    SenderEvent::TransferStarted => self.is_sending = true,
                                    SenderEvent::TransferCompleted => self.is_sent = true,
                                    SenderEvent::Error(ui_err) => {
                                        self.ui_error = Some(ui_err);
                                    }
                                    SenderEvent::SenderNetworkInfo(sn) => {
                                        self.sender_network_info = Some(sn)
                                    }
                                    SenderEvent::ReceiverNetworkInfo(rn) => {
                                        self.receiver_network_info = Some(rn)
                                    }

                                    _ => {}
                                }
                            }

                            if let (Some(handshake_state), Some(hd)) =
                                (&self.handshake_state, &self.handshake_data)
                            {
                                sender_status_card(
                                    ui,
                                    handshake_state,
                                    &hd.secrte_code,
                                    self.is_sending,
                                    self.is_sent,
                                    &mut clipboard,
                                );
                                ui.add_space(10.0);
                            }

                            if let (Some(metadata), (hash), Some(handshake_state)) =
                                (&self.file_metadata, &self.file_hash, &self.handshake_state)
                            {
                                sender_card_single_box(
                                    ui,
                                    metadata,
                                    hash,
                                    self.sender_network_info.clone(),
                                    self.receiver_network_info.clone(),
                                );
                            }

                            if let Some(tp) = &self.transfer_progress {
                                progress_bar(ui, &tp, &cmd_tx, &cond_var);
                            }

                            completion_popup(ctx, ui, self.is_sent, &mut mode, true);
                            error_popup(ctx, &mut self.ui_error, &mut mode);
                        });
                    }

                    Mode::Receive => {
                        let b = top_bar(
                            ui,
                            egui::Color32::from_rgb(180, 100, 255),
                            &mut mode,
                            &cmd_tx,
                        );
                        if b {
                            cancel_confirm.open = true;
                        }

                        cancel_transfer_popup(ctx, &mut cancel_confirm, false, &mut mode, || {
                            cmd_tx.send(Command::Cancel);
                        });

                        while let Ok(ev) = rec_rx.try_recv() {
                            match ev {
                                ReceiverState::FileState(meta) => {
                                    self.file_metadata = Some(meta);
                                }
                                ReceiverState::RecieveCompleted => {
                                    self.completion_status = Some(ReceiverState::RecieveCompleted);
                                }
                                ReceiverState::FileHash(st) => {
                                    self.file_hash = st;
                                }
                                ReceiverState::HandshakeState(hs) => {
                                    self.received_handshake_state = Some(hs);
                                }
                                ReceiverState::ReceivedBytes(bytes) => {
                                    if let Some(meta) = &self.file_metadata {
                                        let tp = TransferProgress {
                                            sent: bytes,
                                            total: meta.raw_bytes,
                                        };
                                        self.transfer_progress = Some(tp);
                                    } else {
                                        let tp = TransferProgress {
                                            sent: bytes,
                                            total: 0,
                                        };
                                        self.transfer_progress = Some(tp);
                                    }
                                }
                                ReceiverState::Error(e) => {
                                    self.ui_error = Some(e);
                                }
                                _ => {}
                            }
                        }

                        ui.vertical_centered(|ui| {
                            ui.add_space(30.0);

                            while let Ok(ev) = ui_rx.try_recv() {
                                match ev {
                                    ReceiverUiState::Confirming => {
                                        self.ui_state = Some(ReceiverUiState::Confirming);
                                    }
                                    ReceiverUiState::Receiving => {
                                        self.ui_state = Some(ReceiverUiState::Receiving);
                                    }
                                    _ => {}
                                }
                            }

                            initial_receive_card(
                                ui,
                                &mut receiver_secret,
                                &cmd_tx,
                                &self.received_handshake_state,
                                matches!(self.ui_state, Some(ReceiverUiState::Receiving)),
                                matches!(
                                    self.completion_status,
                                    Some(ReceiverState::RecieveCompleted)
                                ),
                            );

                            if let Some(state) = &self.ui_state {
                                match *state {
                                    ReceiverUiState::Confirming => {
                                        receive_file_popup(
                                            ui,
                                            &self.file_metadata,
                                            &self.file_hash,
                                            ctx,
                                            &cmd_tx,
                                            &mut mode,
                                        );
                                    }
                                    ReceiverUiState::Receiving => {
                                        receiver_card_single_box(
                                            ui,
                                            &mut receiver_secret,
                                            &cmd_tx,
                                            &self.file_metadata,
                                            &self.file_hash,
                                            ctx,
                                        );

                                        ui.add_space(10.0);

                                        if let Some(tp) = &self.transfer_progress {
                                            progress_bar(ui, &tp, &cmd_tx, &cond_var);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        });

                        completion_popup(
                            ctx,
                            ui,
                            matches!(
                                self.completion_status,
                                Some(ReceiverState::RecieveCompleted)
                            ),
                            &mut mode,
                            false,
                        );
                        error_popup(ctx, &mut self.ui_error, &mut mode);
                    }
                });
        })
    }
}

fn completion_popup(
    ctx: &Context,
    ui: &mut Ui,
    mut is_completed: bool,
    mode: &mut Mode,
    is_sending: bool,
) {
    if !is_completed {
        return;
    }

    let heading = if is_sending {
        "File sent successfully"
    } else {
        "File received successfully"
    };
    Window::new("Transfer Complete")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(12.0);

                ui.heading(heading);
            });

            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("OK").clicked() {
                        *mode = Mode::Idle
                    }
                });
            });
        });
}

#[derive(PartialEq, Copy, Clone)]
enum Mode {
    Idle,
    Send,
    Receive,
}

fn grid_row(ui: &mut Ui, key: &str, val: &str) {
    ui.label(RichText::new(key).color(Color32::from_gray(150)));
    ui.label(RichText::new(val).color(Color32::from_gray(220)));
    ui.end_row();
}

fn action_button_compact(ui: &mut Ui, label: &str, accent: Color32) -> Response {
    ui.add(
        Button::new(RichText::new(label).color(Color32::BLACK).strong())
            .fill(accent)
            .corner_radius(CornerRadius::same(6))
            .min_size(vec2(140.0, 36.0)),
    )
}

fn mini_action_button(ui: &mut Ui, icon: &str, tooltip: &str) -> Response {
    ui.add(
        Button::new(icon)
            .corner_radius(CornerRadius::same(6))
            .min_size(vec2(32.0, 32.0)),
    )
    .on_hover_text(tooltip)
}

fn timeline_step(ui: &mut egui::Ui, active: bool, label: &str, accent: egui::Color32) {
    let bg = if active {
        accent
    } else {
        egui::Color32::from_gray(55)
    };

    let text_color = if active {
        egui::Color32::BLACK
    } else {
        egui::Color32::from_gray(170)
    };

    let font_id = egui::FontId::proportional(11.0);
    let text = label.to_owned();

    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        egui::FontId::proportional(11.0),
        text_color,
    );

    let padding = egui::vec2(10.0, 6.0);
    let size = galley.size() + padding * 2.0;

    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());

    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(6), bg);

    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        font_id,
        text_color,
    );
}

fn timeline_connector(ui: &mut egui::Ui, active: bool) {
    let color = if active {
        egui::Color32::from_rgb(120, 190, 255)
    } else {
        egui::Color32::from_gray(70)
    };

    let size = egui::vec2(20.0, 3.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());

    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(2), color);
}

fn full_width_box(ui: &mut Ui, title: &str, accent: Color32, content: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(Color32::from_rgb(18, 18, 24))
        .stroke(Stroke::new(1.0, Color32::from_rgb(40, 40, 50)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).size(14.0).color(accent).strong());
            ui.add_space(12.0);
            content(ui);
        });
}

fn section_box(ui: &mut Ui, title: &str, accent: Color32, add: impl FnOnce(&mut Ui)) {
    egui::Frame::group(ui.style())
        .fill(Color32::from_rgb(14, 14, 20))
        .stroke(Stroke::new(1.0, Color32::from_rgb(35, 35, 45)))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.label(RichText::new(title).size(12.0).color(accent).strong());
            ui.add_space(8.0);
            add(ui);
        });
}

fn render_step(
    ui: &mut egui::Ui,
    current: &SenderHandShakeState,
    step: &SenderHandShakeState,
    label: &str,
    accent: Color32,
) {
    let completed = current >= step;
    timeline_step(ui, completed, label, accent);
}

fn render_connector(
    ui: &mut egui::Ui,
    current: &SenderHandShakeState,
    next: &SenderHandShakeState,
) {
    let completed = current >= next;
    timeline_connector(ui, completed);
}

#[derive(PartialEq)]
enum StepType {
    Handshake(&'static SenderHandShakeState),
    TransferStarted,
    TransferCompleted,
}

fn sender_status_card(
    ui: &mut Ui,
    handshake_state: &SenderHandShakeState,
    secret_code: &String,
    is_sending: bool,
    is_sent: bool,
    clipboard: &mut Clipboard,
) {
    let accent = Color32::from_rgb(100, 180, 255);

    full_width_box(ui, "Sender", accent, |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;

            let steps = [
                (
                    "Initialize",
                    StepType::Handshake(&SenderHandShakeState::Initialized),
                ),
                (
                    "Secret Derived",
                    StepType::Handshake(&SenderHandShakeState::SecretDerived),
                ),
                (
                    "Verifying Secret",
                    StepType::Handshake(&SenderHandShakeState::VerifyingSecret),
                ),
                (
                    "Secret Verified",
                    StepType::Handshake(&SenderHandShakeState::SecretVerified),
                ),
                (
                    "Public Key Sent",
                    StepType::Handshake(&SenderHandShakeState::PublicKeySent),
                ),
                (
                    "Public Key Received",
                    StepType::Handshake(&SenderHandShakeState::PublicKeyReceived),
                ),
                (
                    "Shared Secret",
                    StepType::Handshake(&SenderHandShakeState::DeriveSharedSecret),
                ),
                (
                    "Transcript",
                    StepType::Handshake(&SenderHandShakeState::DeriveTranscript),
                ),
                (
                    "Handshake Complete",
                    StepType::Handshake(&SenderHandShakeState::HandshakeCompleted),
                ),
                ("Transfer Started", StepType::TransferStarted),
                ("Transfer Completed", StepType::TransferCompleted),
            ];

            for (i, (label, step_type)) in steps.iter().enumerate() {
                let (is_active, is_completed) = match step_type {
                    StepType::Handshake(state) => {
                        let is_current = handshake_state == *state;
                        let is_past = handshake_state > state;
                        (is_current, is_past)
                    }
                    StepType::TransferStarted => (is_sending && !is_sent, is_sent || is_sending),
                    StepType::TransferCompleted => (is_sent, is_sent),
                };

                let color = if is_active {
                    accent
                } else if is_completed {
                    accent.gamma_multiply(0.7)
                } else {
                    Color32::from_gray(100)
                };

                ui.label(RichText::new(*label).color(color));

                if i < steps.len() - 1 {
                    let separator_color = if is_completed {
                        accent.gamma_multiply(0.7)
                    } else {
                        Color32::from_gray(80)
                    };
                    ui.colored_label(separator_color, " › ");
                }
            }
        });
    });

    ui.add_space(12.0);

    section_box(ui, "Transfer secret", accent, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Code:").color(Color32::from_gray(150)));
            ui.label(
                RichText::new(secret_code)
                    .monospace()
                    .color(accent)
                    .strong(),
            );
        });

        ui.set_max_height(3.0);

        ui.vertical(|ui| {
            ui.add_space(13.0);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if action_button_compact(ui, "Copy", accent).clicked() {
                    clipboard.set_text(secret_code);
                }
            });
        });
    });
}

fn sender_card_single_box(
    ui: &mut Ui,
    data: &FileMetadata,
    file_hash: &FileHash,
    sender_data: Option<SenderNetworkInfo>,
    receiver_data: Option<ReceiverNetworkInfo>,
) {
    ui.set_max_width(1000.0);

    let accent = Color32::from_rgb(100, 180, 255);
    ui.add_space(12.0);

    let hash = if let Some(hash) = file_hash.hash {
        format!("{}", hash)
    } else {
        "Calculating Hash..".to_string()
    };

    let sender_data = sender_data.unwrap_or(SenderNetworkInfo {
        ip: "...".to_string(),
        port: "...".to_string(),
    });

    let reciever_data = receiver_data.unwrap_or(ReceiverNetworkInfo {
        ip: "...".to_string(),
        port: "...".to_string(),
    });

    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_min_width(600.0);

            section_box(ui, "File Information", accent, |ui| {
                Grid::new("send_file_grid")
                    .spacing([20.0, 8.0])
                    .show(ui, |ui| {
                        grid_row(ui, "Name:", &data.name);
                        grid_row(ui, "Path:", &data.path);
                        grid_row(ui, "Size:", &data.size);
                        grid_row(ui, "Type:", &data.file_type);
                        grid_row(ui, "Hash:", &hash);
                        grid_row(ui, "Last Modified:", &data.modified_date);
                    });
            });
        });

        ui.add_space(5.0);

        ui.vertical(|ui| {
            section_box(ui, "Network", accent, |ui| {
                Grid::new("network_grid")
                    .spacing([20.0, 8.0])
                    .show(ui, |ui| {
                        grid_row(ui, "Public IP:", &sender_data.ip);
                        grid_row(ui, "Port:", &sender_data.port);

                        grid_row(ui, "Peer IP:", &reciever_data.ip);
                        grid_row(ui, "Peer Port:", &reciever_data.port);

                        grid_row(ui, "Transport:", "TCP");
                        grid_row(ui, "Role:", "Sender");
                    });
            });
        });

        ui.add_space(15.0);
        ui.vertical(|ui| {
            section_box(ui, "Security", accent, |ui| {
                Grid::new("security_grid")
                    .spacing([20.0, 8.0])
                    .show(ui, |ui| {
                        grid_row(ui, "Key Exchange:", "X25519");
                        grid_row(ui, "Key Derivation:", "HKDF");
                        grid_row(ui, "Encryption:", "ChaCha20-Poly1305");

                           ui.label("Forward Secrecy:");
            let resp = ui.colored_label(Color32::WHITE, "Yes");
            resp.on_hover_text("Ensures session keys are ephemeral, so past communications cannot be decrypted even if long term keys are compromised.");
            ui.end_row();

                        grid_row(ui, "File Hash:", "BLAKE3");
                        ui.label("Secret Code:");
            let sc = ui.colored_label(Color32::WHITE, "Base32");
            sc.on_hover_text(
                "The Secret Code encodes the sender's IP and port using Base32 and incorporates 16 bytes of OS-random data for added randomness."
            );
            ui.end_row();
                    });
            });

        });

    });

    ui.add_space(12.0);
}

fn progress_bar(
    ui: &mut Ui,
    progress: &TransferProgress,
    cmd_tx: &Sender<Command>,
    condvar: &Arc<(Mutex<bool>, Condvar)>,
) {
    let fraction = progress.fraction();
    let desired_height = 24.0;

    ui.horizontal(|ui| {
        let available_width = ui.available_width();

        let (rect, response) =
            ui.allocate_exact_size(Vec2::new(available_width, desired_height), Sense::hover());
        let painter = ui.painter();

        painter.rect_filled(rect, 6.0, Color32::from_gray(50));
        painter.rect_filled(
            Rect::from_min_max(
                rect.min,
                pos2(rect.min.x + fraction * rect.width(), rect.max.y),
            ),
            6.0,
            Color32::from_rgb(
                (50.0 + 150.0 * fraction) as u8,
                (200.0 - 50.0 * fraction) as u8,
                100,
            ),
        );

        let percent_text = format!(
            "{:.1}% ({}/{})",
            progress.percent(),
            progress.sent,
            progress.total
        );
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            percent_text,
            TextStyle::Button.resolve(ui.style()),
            Color32::BLACK, // readable
        );

        if response.hovered() {
            painter.text(
                rect.center_bottom() + vec2(0.0, 12.0),
                Align2::CENTER_TOP,
                format!("Progress {:.1}%", progress.percent()),
                TextStyle::Small.resolve(ui.style()),
                Color32::WHITE,
            );
        }
    });

    ui.add_space(4.0);

    ui.horizontal(|ui| {
        if ui.button("⏸ Pause").clicked() {
            let _ = cmd_tx.send(Command::Pause);
            let (lock, _) = &**condvar;
            let mut paused = lock.lock().unwrap();
            *paused = true;
        }

        if ui.button("▶ Resume").clicked() {
            let (lock, condvar) = &**condvar;
            let mut paused = lock.lock().unwrap();
            *paused = false;
            condvar.notify_all();
        }
    });
}

#[derive(Default, Clone)]
pub struct CancelConfirm {
    pub open: bool,
}

fn cancel_transfer_popup(
    ctx: &egui::Context,
    confirm: &mut CancelConfirm,
    is_sending: bool,
    mode: &mut Mode,
    on_confirm_cancel: impl FnOnce(),
) {
    if !confirm.open {
        return;
    }

    Window::new("Cancel Transfer?")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(8.0);

                let action = if is_sending { "sending" } else { "receiving" };
                let cur_mode = if is_sending {
                    Mode::Send
                } else {
                    Mode::Receive
                };
                ui.label(
                    egui::RichText::new(format!("Are you sure you want to cancel {}?", action))
                        .size(15.0)
                        .strong(),
                );

                ui.add_space(6.0);

                ui.label(
                    egui::RichText::new("Any partially transferred data will be discarded.")
                        .color(egui::Color32::from_gray(160)),
                );

                ui.add_space(14.0);

                ui.horizontal(|ui| {
                    ui.add_space(20.0);

                    if ui.button("Continue").clicked() {
                        confirm.open = false;
                        *mode = cur_mode;
                    }

                    let cancel_btn = ui.add(
                        egui::Button::new(
                            egui::RichText::new("Cancel Transfer").color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(180, 60, 60)),
                    );

                    if cancel_btn.clicked() {
                        confirm.open = false;
                        on_confirm_cancel();
                        *mode = Mode::Idle;
                    }
                });

                ui.add_space(8.0);
                if ctx.input(|x| x.key_pressed(Key::Escape)) {
                    confirm.open = false;
                }
            });
        });
}

use crate::state::ReceiverState;

fn receive_file_popup(
    ui: &mut Ui,
    metadata: &Option<FileMetadata>,
    file_hash: &FileHash,
    ctx: &Context,
    cmd_tx: &Sender<Command>,
    mode: &mut Mode,
) {
    let accent = Color32::from_rgb(180, 100, 255);
    ui.set_max_width(1000.0);

    let hash = if let Some(hash) = file_hash.hash {
        format!("{}", hash)
    } else {
        "Computing Hash..".to_string()
    };

    let mut window_open = true;
    egui::Window::new("Incoming File")
        .open(&mut window_open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(ctx, |ui| {
            ui.set_min_width(360.0);
            ui.add_space(8.0);

            if let Some(metadata) = metadata {
                Grid::new(ui.id().with("recv_file_popup_grid"))
                    .num_columns(2)
                    .spacing([20.0, 8.0])
                    .show(ui, |ui| {
                        grid_row(ui, "Name:", &metadata.name);
                        grid_row(ui, "Size:", &metadata.size);
                        grid_row(ui, "Type:", &metadata.file_type);
                        grid_row(ui, "Path:", &metadata.path);
                    });

                ui.add_space(12.0);
                ui.label(
                    RichText::new("BLAKE3 Hash")
                        .size(10.0)
                        .color(Color32::from_rgb(120, 120, 140)),
                );
                hash_display(ui, &hash, accent);

                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Continue").clicked() {
                            let _ = cmd_tx.send(Command::Decision(Decision::Accept));
                        }
                        if ui.button("Cancel").clicked() {
                            let _ = cmd_tx.send(Command::Decision(Decision::Reject));
                            *mode = Mode::Idle;
                        }
                    });
                });
            } else {
                ui.label("Waiting for metadata...");
            }
        });
    ui.add_space(12.0);
}

fn render_receive_step(
    ui: &mut egui::Ui,
    current: &ReceiveHandShakeState,
    step: &ReceiveHandShakeState,
    label: &str,
    accent: Color32,
) {
    let completed = current >= step;
    timeline_step(ui, completed, label, accent);
}

fn render_receive_connector(
    ui: &mut egui::Ui,
    current: &ReceiveHandShakeState,
    next: &ReceiveHandShakeState,
) {
    let completed = current >= next;
    timeline_connector(ui, completed);
}

fn initial_receive_card(
    ui: &mut Ui,
    secret: &mut String,
    cmd_tx: &Sender<Command>,
    handshake_state: &Option<ReceiveHandShakeState>,
    is_receiving: bool,
    received: bool,
) {
    let accent = Color32::from_rgb(180, 100, 255);
    ui.set_max_width(1000.0);

    full_width_box(ui, "Receiver", accent, |ui| {
        if let Some(handshake_state) = handshake_state {
            ui.horizontal(|ui| {
                render_receive_step(
                    ui,
                    &handshake_state,
                    &ReceiveHandShakeState::Initialized,
                    "Handshake Initialized",
                    accent,
                );

                render_receive_connector(
                    ui,
                    &handshake_state,
                    &ReceiveHandShakeState::PublicKeySent,
                );

                render_receive_step(
                    ui,
                    &handshake_state,
                    &ReceiveHandShakeState::PublicKeySent,
                    "Public Key Sent",
                    accent,
                );

                render_receive_connector(
                    ui,
                    &handshake_state,
                    &ReceiveHandShakeState::PublicKeyReceived,
                );

                render_receive_step(
                    ui,
                    &handshake_state,
                    &ReceiveHandShakeState::PublicKeyReceived,
                    "Public Key Received",
                    accent,
                );

                render_receive_connector(
                    ui,
                    &handshake_state,
                    &ReceiveHandShakeState::DeriveSharedSecret,
                );

                render_receive_step(
                    ui,
                    &handshake_state,
                    &ReceiveHandShakeState::DeriveSharedSecret,
                    "Shared Secret Derived",
                    accent,
                );

                render_receive_connector(
                    ui,
                    &handshake_state,
                    &ReceiveHandShakeState::DeriveTranscript,
                );

                render_receive_step(
                    ui,
                    &handshake_state,
                    &ReceiveHandShakeState::DeriveTranscript,
                    "Transcript Derived",
                    accent,
                );

                timeline_connector(ui, is_receiving);
                timeline_step(ui, is_receiving, "Receiving Started", accent);

                timeline_connector(ui, received);
                timeline_step(ui, received, "Receiving Completed", accent);
            });
        }

        ui.add_space(12.0);

        section_box(ui, "Transfer authentication", accent, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(secret)
                        .font(FontId::monospace(20.0))
                        .desired_width(800.0)
                        .hint_text("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"),
                );
                ui.add_space(0.0);

                if action_button_compact(ui, "Authenticate", accent).clicked() {
                    let receiver = Command::StartReciver {
                        code: secret.clone(),
                    };
                    let _ = cmd_tx.send(receiver);
                }

                ui.add_space(12.0);
            });
        });

        ui.add_space(12.0);
    });
}

fn receiver_card_single_box(
    ui: &mut Ui,
    save_location: &mut String,
    cmd_tx: &Sender<Command>,
    metadata: &Option<FileMetadata>,
    file_hash: &FileHash,
    ctx: &Context,
) {
    let accent = Color32::from_rgb(180, 100, 255);
    ui.set_max_width(1000.0);

    full_width_box(ui, "Receiver", accent, |ui| {
        let hash = if let Some(hash) = file_hash.hash {
            format!("{}", hash)
        } else {
            "Computing Hash..".to_string()
        };

        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_max_width(620.0);

                if let Some(metadata) = metadata {
                    section_box(ui, "File information", accent, |ui| {
                        Grid::new("send_file_grid")
                            .spacing([20.0, 8.0])
                            .show(ui, |ui| {
                                grid_row(ui, "Name:", &metadata.name);
                                grid_row(ui, "Path:", &metadata.path);
                                grid_row(ui, "Size:", &metadata.size);
                                grid_row(ui, "Type:", &metadata.file_type);
                                grid_row(ui, "Hash:", &hash);
                                grid_row(ui, "Last Modified:", &metadata.modified_date);
                            });
                    });
                }

                ui.add_space(16.0);
            });
        });
        ui.add_space(12.0);
    });
}

fn error_popup(ctx: &egui::Context, error: &mut Option<UiError>, mode: &mut Mode) {
    let Some(err) = error else { return };
    let err = err.clone();
    egui::Window::new("Error")
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
        .show(ctx, |ui| {
            egui::Frame::popup(ui.style()).show(ui, |ui| {
                ui.set_min_width(300.0);

                ui.label(
                    egui::RichText::new("Error")
                        .size(16.0)
                        .strong()
                        .color(egui::Color32::RED),
                );

                ui.add_space(8.0);

                ui.label(err.title());
                if let Some(details) = err.details() {
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(details)
                            .small()
                            .color(egui::Color32::from_gray(160)),
                    );
                }

                ui.add_space(12.0);

                if ui.button("OK").clicked() {
                    *error = None;
                    match mode {
                        Mode::Send => *mode = Mode::Send,
                        Mode::Receive => *mode = Mode::Receive,
                        _ => {}
                    }
                }
            });
        });
}

fn top_bar(
    ui: &mut egui::Ui,
    color: egui::Color32,
    mode: &mut Mode,
    cmd_tx: &Sender<Command>,
) -> bool {
    let mut home_button_clicked = false;
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(16, 16, 22))
        .inner_margin(egui::Margin::symmetric(20, 16))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if home_button(ui).clicked() {
                    home_button_clicked = true;
                }
                ui.add_space(20.0);
                let (bar_rect, _) =
                    ui.allocate_exact_size(egui::vec2(4.0, 24.0), egui::Sense::hover());
                ui.painter().rect_filled(bar_rect, 2.0, color);
                ui.add_space(12.0);
            });
        });
    home_button_clicked
}

fn home_button(ui: &mut egui::Ui) -> egui::Response {
    let size = egui::vec2(100.0, 32.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    let bg = if response.hovered() {
        egui::Color32::from_rgb(30, 30, 38)
    } else {
        egui::Color32::from_rgb(22, 22, 28)
    };
    ui.painter().rect_filled(rect, 6.0, bg);
    ui.painter().text(
        rect.left_center() + egui::vec2(36.0, 0.0),
        egui::Align2::LEFT_CENTER,
        "Home",
        egui::FontId::proportional(13.0),
        egui::Color32::from_rgb(140, 140, 160),
    );
    response
}

fn mode_selection_card(ui: &mut egui::Ui, mode: &mut Mode, cmd_tx: &Sender<Command>) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(20, 20, 28))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 45, 60)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::same(32))
        .show(ui, |ui| {
            ui.set_width(380.0);
            ui.label(
                egui::RichText::new("Select Transfer Mode")
                    .size(16.0)
                    .color(egui::Color32::from_rgb(200, 200, 220))
                    .strong(),
            );
            ui.add_space(30.0);
            if gradient_button(
                ui,
                "📤",
                "Send Files",
                egui::Color32::from_rgb(80, 150, 255),
                egui::Color32::from_rgb(50, 100, 200),
            )
            .clicked()
            {
                let cwd = std::env::current_dir().expect("error");

                let Some(file_path) = FileDialog::new().set_directory(&cwd).pick_file() else {
                    println!("No file selected");
                    return;
                };
                let s = Command::StartSender {
                    file_path: file_path.clone(),
                };
                if cmd_tx.send(s).is_ok() {
                    info!("successfully sent - {}", file_path.display());
                } else {
                    eprintln!("Error: Failed to send");
                }

                *mode = Mode::Send;
            }
            ui.add_space(16.0);
            if gradient_button(
                ui,
                "📥",
                "Receive Files",
                egui::Color32::from_rgb(160, 80, 255),
                egui::Color32::from_rgb(120, 50, 200),
            )
            .clicked()
            {
                *mode = Mode::Receive;
            }
        });
}

fn hash_display(ui: &mut egui::Ui, hash: &str, _: egui::Color32) {
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(egui::Color32::from_rgb(12, 12, 18))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(30, 30, 40)))
            .corner_radius(CornerRadius::same(4))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(hash)
                        .size(9.0)
                        .color(egui::Color32::from_rgb(160, 160, 180))
                        .monospace(),
                );
            });
        mini_action_button(ui, "📋", "Copy");
    });
}

fn gradient_button(
    ui: &mut egui::Ui,
    icon: &str,
    label: &str,
    c1: egui::Color32,
    c2: egui::Color32,
) -> egui::Response {
    let size = egui::vec2(320.0, 64.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    let (color1, color2) = if response.hovered() {
        (c1.gamma_multiply(1.1), c2.gamma_multiply(1.1))
    } else {
        (c1, c2)
    };

    let steps = 20;
    for i in 0..steps {
        let t = i as f32 / steps as f32;
        let color = egui::Color32::from_rgb(
            (color1.r() as f32 * (1.0 - t) + color2.r() as f32 * t) as u8,
            (color1.g() as f32 * (1.0 - t) + color2.g() as f32 * t) as u8,
            (color1.b() as f32 * (1.0 - t) + color2.b() as f32 * t) as u8,
        );
        let x_start = rect.min.x + rect.width() * t;
        let x_end = rect.min.x + rect.width() * ((i + 1) as f32 / steps as f32);
        ui.painter().rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(x_start, rect.min.y),
                egui::pos2(x_end, rect.max.y),
            ),
            8.0,
            color,
        );
    }

    ui.painter().text(
        rect.left_center() + egui::vec2(24.0, 0.0),
        egui::Align2::LEFT_CENTER,
        icon,
        egui::FontId::proportional(28.0),
        egui::Color32::WHITE,
    );
    ui.painter().text(
        rect.center() + egui::vec2(10.0, 0.0),
        egui::Align2::CENTER_CENTER,
        label,
        egui::FontId::proportional(18.0),
        egui::Color32::WHITE,
    );
    response
}
