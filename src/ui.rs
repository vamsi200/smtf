#![allow(unused)]
use arboard::Clipboard;
use blake3::Hash;
use eframe::NativeOptions;
use egui::{epaint::FontsView, *};
use log::info;
use rfd::FileDialog;
use std::{
    net::TcpListener,
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};

use crate::{
    handshake::{decode, encode, sender, Decision},
    helper::get_socket_addr,
    state::{
        Command, FileHash, FileMetadata, HandshakeData, ReceiveHandShakeState, ReceiverUiState,
        SenderEvent, SenderHandShakeState, TransferProgress,
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
}

impl AppState {
    pub fn app(
        mut self,
        ev_rx: Receiver<SenderEvent>,
        cmd_tx: Sender<Command>,
        rec_rx: Receiver<ReceiverState>,
        ui_rx: Receiver<ReceiverUiState>,
    ) -> eframe::Result<()> {
        let options = NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1280.0, 800.0])
                .with_min_inner_size([900.0, 600.0]),
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
                            "SENDER",
                            egui::Color32::from_rgb(100, 180, 255),
                            &mut mode,
                            &cmd_tx,
                        );

                        // should I keep this pattern?
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
                                    _ => {}
                                }
                            }

                            // This is a stupid pattern bro
                            if let (Some(handshake_state), Some(hd)) =
                                (&self.handshake_state, &self.handshake_data)
                            {
                                sender_status_card(
                                    ui,
                                    handshake_state,
                                    &hd.secrte_code,
                                    self.is_sending,
                                    self.is_sent,
                                );
                                ui.add_space(10.0);
                            }

                            if let (Some(metadata), (hash), Some(handshake_state)) =
                                (&self.file_metadata, &self.file_hash, &self.handshake_state)
                            {
                                sender_card_single_box(ui, metadata, hash);
                            }

                            if let Some(tp) = &self.transfer_progress {
                                progress_bar(ui, &tp);
                            }

                            completion_popup(ctx, ui, self.is_sent, &mut mode);
                        });
                    }

                    Mode::Receive => {
                        let b = top_bar(
                            ui,
                            "RECEIVER",
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
                                            progress_bar(ui, &tp);
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
                        );
                    }
                });
        })
    }
}

fn completion_popup(ctx: &Context, ui: &mut Ui, mut is_completed: bool, mode: &mut Mode) {
    if !is_completed {
        return;
    }

    Window::new("Transfer Complete")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(12.0);
                ui.heading("File received successfully");
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

fn sender_status_card(
    ui: &mut Ui,
    handshake_state: &SenderHandShakeState,
    secret_code: &String,
    is_sending: bool,
    is_sent: bool,
) {
    let accent = Color32::from_rgb(100, 180, 255);
    let mut clipboard = Clipboard::new().unwrap();
    full_width_box(ui, "Sender", accent, |ui| {
        ui.horizontal(|ui| {
            render_step(
                ui,
                handshake_state,
                &SenderHandShakeState::Initialized,
                "Handshake Initialized",
                accent,
            );
            render_connector(ui, handshake_state, &SenderHandShakeState::SecretDerived);

            render_step(
                ui,
                handshake_state,
                &SenderHandShakeState::SecretDerived,
                "Secret Derived",
                accent,
            );
            render_connector(ui, handshake_state, &SenderHandShakeState::VerifyingSecret);

            render_step(
                ui,
                handshake_state,
                &SenderHandShakeState::VerifyingSecret,
                "Secret Verification Started",
                accent,
            );
            render_connector(ui, handshake_state, &SenderHandShakeState::SecretVerified);

            render_step(
                ui,
                handshake_state,
                &SenderHandShakeState::SecretVerified,
                "Secret Verified",
                accent,
            );
            render_connector(ui, handshake_state, &SenderHandShakeState::PublicKeySent);

            render_step(
                ui,
                handshake_state,
                &SenderHandShakeState::PublicKeySent,
                "Public Key Sent",
                accent,
            );
            render_connector(
                ui,
                handshake_state,
                &SenderHandShakeState::PublicKeyReceived,
            );

            render_step(
                ui,
                handshake_state,
                &SenderHandShakeState::PublicKeyReceived,
                "Public Key Received",
                accent,
            );
            render_connector(
                ui,
                handshake_state,
                &SenderHandShakeState::DeriveSharedSecret,
            );

            render_step(
                ui,
                handshake_state,
                &SenderHandShakeState::DeriveSharedSecret,
                "Shared Secret Derived",
                accent,
            );
            render_connector(ui, handshake_state, &SenderHandShakeState::DeriveTranscript);

            render_step(
                ui,
                handshake_state,
                &SenderHandShakeState::DeriveTranscript,
                "Transcript Derived",
                accent,
            );
            render_connector(
                ui,
                handshake_state,
                &SenderHandShakeState::HandshakeCompleted,
            );

            render_step(
                ui,
                handshake_state,
                &SenderHandShakeState::HandshakeCompleted,
                "Handshake Completed",
                accent,
            );

            timeline_step(ui, is_sending, "Transfer Started", accent);
            timeline_connector(ui, is_sending);
            timeline_step(ui, is_sent, "Transfer Completed", accent);
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

            ui.add_space(0.0);

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if action_button_compact(ui, "Copy", accent).clicked() {
                    clipboard.set_text(secret_code);
                }
            });
        });
    });
}

fn sender_card_single_box(ui: &mut Ui, data: &FileMetadata, file_hash: &FileHash) {
    ui.set_max_width(1000.0);

    let accent = Color32::from_rgb(100, 180, 255);

    ui.add_space(12.0);

    let hash = if let Some(hash) = file_hash.hash {
        format!("{}", hash)
    } else {
        format!("Calculating Hash..")
    };

    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_max_width(620.0);

            section_box(ui, "File information", accent, |ui| {
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

        ui.add_space(16.0);
    });

    ui.add_space(12.0);
}

fn progress_bar(ui: &mut Ui, progress: &TransferProgress) {
    ui.add(egui::ProgressBar::new(progress.fraction()).text(format!(
        "{:.1}% ({}/{})",
        progress.percent(),
        progress.sent,
        progress.total
    )));
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

fn feature_pill(ui: &mut egui::Ui, icon: &str, text: &str) {
    let size = egui::vec2(140.0, 32.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, 16.0, egui::Color32::from_rgb(22, 22, 30));
    ui.painter().rect_stroke(
        rect,
        16.0,
        egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 50, 65)),
        egui::StrokeKind::Outside,
    );
    ui.painter().text(
        rect.left_center() + egui::vec2(16.0, 0.0),
        egui::Align2::LEFT_CENTER,
        icon,
        egui::FontId::proportional(14.0),
        egui::Color32::from_rgb(150, 150, 170),
    );
    ui.painter().text(
        rect.left_center() + egui::vec2(38.0, 0.0),
        egui::Align2::LEFT_CENTER,
        text,
        egui::FontId::proportional(11.0),
        egui::Color32::from_rgb(140, 140, 160),
    );
}

fn top_bar(
    ui: &mut egui::Ui,
    title: &str,
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
                    // *mode = Mode::Idle;
                }
                ui.add_space(20.0);
                let (bar_rect, _) =
                    ui.allocate_exact_size(egui::vec2(4.0, 24.0), egui::Sense::hover());
                ui.painter().rect_filled(bar_rect, 2.0, color);
                ui.add_space(12.0);
                ui.label(egui::RichText::new(title).size(20.0).color(color).strong());
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
