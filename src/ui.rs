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
        Arc, Condvar, Mutex, mpsc::{Receiver, Sender}
    },
    time::{Duration, Instant},
};

use crate::{
    handshake::{Decision, decode, encode, sender},
    helper::get_socket_addr,
    state::{
        Command, CondState, FileHash, FileMetadata, HandshakeData, ReceiveHandShakeState, ReceiverNetworkInfo, ReceiverUiState, SenderEvent, SenderHandShakeState, SenderNetworkInfo, TransferProgress, UiError
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
    pub is_expanded: bool,
    pub is_transfer_cancelled: bool,
    pub ui_state: Option<ReceiverUiState>,
    pub transfer_progress: Option<TransferProgress>,
    pub received_handshake_state: Option<ReceiveHandShakeState>,
    pub ui_error: Option<UiError>,
    pub sender_network_info: Option<SenderNetworkInfo>,
    pub receiver_network_info: Option<ReceiverNetworkInfo>,
    pub popup_state: PopupState,
}

impl AppState {
    pub fn app(
        mut self,
        ev_rx: Receiver<SenderEvent>,
        cmd_tx: Sender<Command>,
        rec_rx: Receiver<ReceiverState>,
        ui_rx: Receiver<ReceiverUiState>,
        cond_var: Arc<(Mutex<CondState>, Condvar)>,
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
        let expanded_id = egui::Id::new("receiver_secret_expanded");

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
                        self.is_transfer_cancelled = false;

                        receiver_secret = String::new();

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

                        generic_popup(ctx,&mut  self.popup_state, true);

                        cancel_transfer_popup_command_style(
                            ctx,
                            &mut cancel_confirm,
                            true,
                            &mut mode,
                            &cond_var,
                            || {
                                cmd_tx.send(Command::Cancel);
                            },
                        );

                        ui.vertical_centered(|ui| {
                            ui.add_space(5.0);

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
                                    SenderEvent::TransferStarted => {self.is_sending = true},
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
                                    SenderEvent::TransferCancelled => {
                                        self.is_transfer_cancelled = true
                                    }

                                    _ => {}
                                }
                            }


                            if let (Some(handshake_state), Some(hd)) =
                                (&self.handshake_state, &self.handshake_data)
                            {
                            let is_peer_connected = match handshake_state {
                                SenderHandShakeState::VerifyingSecret => false,
                                SenderHandShakeState::Initialized => false,
                                SenderHandShakeState::SecretDerived => false,
                                _ => true,
                            };

                                sender_status_card(
                                    ui,
                                    handshake_state,
                                    &hd.secrte_code,
                                    self.is_sending,
                                    self.is_sent,
                                    &mut clipboard,
                                    &mut self.is_expanded,
                                    is_peer_connected,
                                    &mut self.popup_state,
                                    ctx
                                );
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

                            completion_popup(ctx, self.is_sent, &mut mode, true);
                            error_popup(ctx, &mut self.ui_error, &mut mode, &cond_var);
                            receiver_cancelled_popup(ctx, &mut self.is_transfer_cancelled, &mut mode);

                            

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

                        generic_popup(ctx,&mut  self.popup_state, false);

                        cancel_transfer_popup_command_style(
                            ctx,
                            &mut cancel_confirm,
                            false,
                            &mut mode,
                        &cond_var,
                            || {
                                cmd_tx.send(Command::Cancel);
                            },
                        );

                        while let Ok(ev) = rec_rx.try_recv() {
                            match ev {
                                ReceiverState::Connecting => {
                                        self.popup_state = PopupState { popup: Some(PopupKind::Connecting), popup_since: ctx.input(|x|x.time) };
                                }
                                ReceiverState::Connected => {
                                    self.popup_state = PopupState { popup: Some(PopupKind::Connected), popup_since: ctx.input(|x|x.time) };
                                }
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
                                ReceiverState::SenderNetworkInfo(sn) => {
                                    self.sender_network_info = Some(sn)
                                }
                                ReceiverState::ReceiverNetworkInfo(rn) => {
                                    self.receiver_network_info = Some(rn)
                                }
                                _ => {}
                            }
                        }

                        ui.vertical_centered(|ui| {
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

                            ui.add_space(5.0);
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
                                &mut self.is_expanded,
                            );
                            ui.add_space(5.0);

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
                                            self.sender_network_info.clone(),
                                            self.receiver_network_info.clone(),
                                            ctx,
                                        );

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
                            matches!(
                                self.completion_status,
                                Some(ReceiverState::RecieveCompleted)
                            ),
                            &mut mode,
                            false,
                        );
                        error_popup(ctx, &mut self.ui_error, &mut mode, &cond_var);
                    }
                });
        })
    }
}

pub enum PopupKind {
    Connecting,
    Connected,
    Copied,
}

pub struct PopupState {
    pub popup: Option<PopupKind>,
    pub popup_since: f64,
}

pub fn generic_popup(ctx: &egui::Context, ui_state: &mut PopupState, is_sender: bool) {
    let Some(kind) = &ui_state.popup else { return };

    let elapsed = ctx.input(|i| i.time) - ui_state.popup_since;

    if elapsed > 1.0 {
        ui_state.popup = None;  
        return;
    }

    let text = match kind {
        PopupKind::Connecting => "> trying to connect",
        PopupKind::Connected  => "> successfully connected",
        PopupKind::Copied     => "> successfully copied",
    };

    let accent = if is_sender {
            Color32::from_rgb(100, 180, 255)

    } else {Color32::from_rgb(180, 100, 255)};

    egui::Area::new(Id::new("connection_popup"))
        .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -16.0))
        .order(egui::Order::Foreground)
        .interactable(false)
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(15, 15, 20))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(60)))
                .corner_radius(egui::CornerRadius::same(2))
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(text)
                            .monospace()
                            .color(accent),
                    );
                });
        });
}

fn completion_popup(ctx: &egui::Context, is_completed: bool, mode: &mut Mode, is_sending: bool) {
    if !is_completed {
        return;
    }

    let accent = egui::Color32::from_rgb(100, 200, 100);

    let heading = if is_sending {
        "TRANSFER COMPLETE —  FILE SENT"
    } else {
        "TRANSFER COMPLETE —  FILE RECEIVED"
    };

    let mut window_open = true;
    egui::Window::new("")
        .open(&mut window_open)
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .frame(
            egui::Frame::popup(&ctx.style())
                .corner_radius(2.0)
                .inner_margin(egui::Margin::same(20))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(60)))
                .fill(egui::Color32::from_rgb(15, 15, 20)),
        )
        .show(ctx, |ui| {
            ui.set_width(400.0);

            ui.horizontal(|ui| {
                ui.colored_label(accent, "> ");
                ui.label(
                    egui::RichText::new("STATUS")
                        .monospace()
                        .color(accent)
                        .strong(),
                );
            });

            ui.add_space(15.0);
            ui.separator();
            ui.add_space(15.0);

            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(heading)
                        .monospace()
                        .size(14.0)
                        .color(egui::Color32::from_gray(220)),
                );

                ui.add_space(8.0);

                let info_frame = egui::Frame::new()
                    .fill(egui::Color32::from_rgb(25, 25, 30))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(70)))
                    .inner_margin(egui::Margin::symmetric(12, 8));

                info_frame.show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("Operation completed without errors.")
                            .monospace()
                            .size(12.0)
                            .color(egui::Color32::from_gray(160)),
                    );
                });
            });

            ui.add_space(20.0);
            ui.separator();
            ui.add_space(20.0);

            ui.horizontal(|ui| {
                let ok_btn = ui.add(
                    egui::Button::new(
                        egui::RichText::new("[ RETURN ]")
                            .monospace()
                            .color(egui::Color32::from_rgb(180, 220, 180)),
                    )
                    .fill(egui::Color32::from_rgb(20, 30, 25))
                    .stroke(egui::Stroke::new(
                        1.0,
                        egui::Color32::from_rgb(100, 200, 100),
                    ))
                    .corner_radius(2.0),
                );

                if ok_btn.clicked() {
                    *mode = Mode::Idle;
                }
            });
        });

    if !window_open {
        *mode = Mode::Idle;
    }
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
    is_expanded: &mut bool,
    is_peer_connected: bool,
    is_copied: &mut PopupState,
    ctx: &Context
) {
    let accent = Color32::from_rgb(100, 180, 255);
    let expanded_id = egui::Id::new("transfer_secret_expanded");

    let status_frame = Frame::window(&ui.style())
        .fill(Color32::from_rgb(15, 15, 20))
        .stroke(Stroke::new(1.0, Color32::from_gray(60)))
        .inner_margin(Margin::same(20))
        .corner_radius(2.0);

    status_frame.show(ui, |ui| {
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("> [STATUS]")
                        .color(accent)
                        .monospace()
                        .strong(),
                );
            });

            ui.add_space(8.0);

            ui.horizontal_wrapped(|ui| {
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
                        StepType::TransferStarted => {
                            (is_sending && !is_sent, is_sent || is_sending)
                        }
                        StepType::TransferCompleted => (is_sent, is_sent),
                    };

                    let color = if is_active {
                        accent
                    } else if is_completed {
                        accent.gamma_multiply(0.7)
                    } else {
                        Color32::from_gray(100)
                    };

                    ui.label(RichText::new(*label).monospace().color(color));

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

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(10.0);
        const SECRET_PANEL_WIDTH: f32 = 360.0;

        if is_peer_connected{ 
            *is_expanded = false;
        }

        ui.data_mut(|d| d.insert_temp(expanded_id.with("prev_connected"), is_peer_connected));

        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                let arrow = if *is_expanded { "▼" } else { "▶" };

                let arrow_response = ui.add(
                    egui::Label::new(RichText::new(arrow).monospace().color(
                        if is_peer_connected {
                            Color32::from_gray(90)
                        } else {
                            accent
                        },
                    ))
                    .sense(egui::Sense::click()),
                );

                ui.label(RichText::new("SECRET").monospace().strong().color(
                    if is_peer_connected {
                        Color32::from_gray(90)
                    } else {
                        accent
                    },
                ));

                if !*is_expanded {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("(click to show secret code)")
                            .monospace()
                            .color(Color32::from_gray(120)),
                    );
                }

                if arrow_response.clicked() {
                    *is_expanded = !*is_expanded;
                }
            });

            if *is_expanded {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Code:").color(Color32::from_gray(150)));

                    ui.label(
                        RichText::new(secret_code)
                            .monospace()
                            .strong()
                            .color(accent),
                    );
                });

                ui.set_max_height(20.0);
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(
                        ui.available_size_before_wrap(),
                        Layout::right_to_left(Align::Center),
                        |ui| {
                            if action_button_compact(ui, "Copy", accent).clicked() {
                                if let Ok(_) = clipboard.set_text(secret_code) {
                                    *is_copied = PopupState { popup: Some(PopupKind::Copied), popup_since: ctx.input(|x|x.time) };

                                }
                            }
                        },
                    );
                });
            }
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
    let accent = Color32::from_rgb(100, 180, 255);
    ui.add_space(8.0);

    let is_peer_connected = receiver_data.is_some();
    if !is_peer_connected {
        ui.add_space(50.0);
    }
    let hash = file_hash
        .hash
        .map(|h| h.to_string())
        .unwrap_or_else(|| "Calculating Hash..".to_string());

    let sender_data = sender_data.unwrap_or(SenderNetworkInfo {
        ip: "...".to_string(),
        port: "...".to_string(),
    });

    let receiver_data = receiver_data.unwrap_or(ReceiverNetworkInfo {
        ip: "...".to_string(),
        port: "...".to_string(),
    });

    let outer_frame = egui::Frame::window(&ui.style())
        .fill(Color32::from_rgb(15, 15, 20))
        .stroke(egui::Stroke::new(1.0, Color32::from_gray(60)))
        .inner_margin(egui::Margin::same(20))
        .corner_radius(2.0);

    outer_frame.show(ui, |ui| {
        ui.set_min_width(ui.available_width());

        ui.horizontal(|ui| {
            ui.colored_label(accent, "> ");
            ui.label(
                egui::RichText::new("[OVERVIEW]")
                    .color(accent)
                    .monospace()
                    .strong(),
            );
        });

        ui.add_space(15.0);

        if ui.available_width() >= 1920.0 {
            ui.horizontal_centered(|ui| {
                ui.vertical(|ui| {
                    file_info_box(ui, accent, data, &hash);
                });
                        ui.add_space(50.0);

                ui.vertical(|ui| {
                    network_box(ui, accent, &sender_data, &receiver_data);
                });
            });
        } else if ui.available_width() >= 1000.0 {
            ui.horizontal_centered(|ui| {
                ui.vertical(|ui| {
                    file_info_box(ui, accent, data, &hash);
                });

                        ui.add_space(50.0);

                ui.vertical(|ui| {
                    network_box(ui, accent, &sender_data, &receiver_data);
                });

            });
        } else {
            ui.vertical_centered(|ui| {
                file_info_box(ui, accent, data, &hash);
                network_box(ui, accent, &sender_data, &receiver_data);
            });
        }
    });
}

fn file_info_box(ui: &mut Ui, accent: Color32, data: &FileMetadata, hash: &str) {
    ui.set_min_width(260.0);

    ui.horizontal(|ui| {
        ui.label(
            RichText::new("FILE INFORMATION")
                .monospace()
                .strong()
                .color(accent),
        );
    });

    ui.add_space(8.0);

    let frame = egui::Frame::new()
        .fill(Color32::from_rgb(25, 25, 30))
        .stroke(Stroke::new(1.0, Color32::from_gray(70)))
        .inner_margin(Margin::symmetric(10, 10))
        .corner_radius(2.0);

    frame.show(ui, |ui| {
        terminal_kv(ui, "Name", &data.name);
        terminal_kv(ui, "Path", &data.path);
        terminal_kv(ui, "Size", &data.size);
        terminal_kv(ui, "Type", &data.file_type);
        terminal_kv(ui, "Hash", hash);
        terminal_kv(ui, "Last Modified", &data.modified_date);
    });
}

fn network_box(
    ui: &mut Ui,
    accent: Color32,
    sender: &SenderNetworkInfo,
    receiver: &ReceiverNetworkInfo,
) {
    ui.set_min_width(260.0);

    ui.horizontal(|ui| {
        ui.label(RichText::new("NETWORK").monospace().strong().color(accent));
    });

    ui.add_space(8.0);

    let frame = egui::Frame::new()
        .fill(Color32::from_rgb(25, 25, 30))
        .stroke(Stroke::new(1.0, Color32::from_gray(70)))
        .inner_margin(Margin::symmetric(10, 10))
        .corner_radius(2.0);

    frame.show(ui, |ui| {
        terminal_kv(ui, "Public IP", &sender.ip);
        terminal_kv(ui, "Port", &sender.port);
        terminal_kv(ui, "Peer IP", &receiver.ip);
        terminal_kv(ui, "Peer Port", &receiver.port);
        terminal_kv(ui, "Transport", "TCP");
        terminal_kv(ui, "Role", "Sender");
    });
}

fn grid_row_cmd(ui: &mut Ui, key: &str, value: &str) {
    ui.label(
        egui::RichText::new(format!("{key}:"))
            .monospace()
            .color(Color32::from_gray(160)),
    );
    ui.label(egui::RichText::new(value).monospace());
    ui.end_row();
}

fn progress_bar(
    ui: &mut Ui,
    progress: &TransferProgress,
    cmd_tx: &Sender<Command>,
    condvar: &Arc<(Mutex<CondState>, Condvar)>,
) {
    ui.add_space(8.0);

    let fraction = progress.fraction();
    let desired_height = 16.0;

    let progress_frame = Frame::window(&ui.style())
        .fill(Color32::from_rgb(15, 15, 20))
        .stroke(Stroke::new(1.0, Color32::from_gray(60)))
        .inner_margin(Margin::same(16))
        .corner_radius(2.0);

    progress_frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.colored_label(Color32::from_rgb(100, 180, 255), "> ");
            ui.label(
                RichText::new("PROGRESS")
                    .color(Color32::from_rgb(100, 180, 255))
                    .monospace()
                    .strong(),
            );
        });

        ui.add_space(12.0);

        ui.horizontal(|ui| {
            let available_width = ui.available_width();

            let (rect, response) =
                ui.allocate_exact_size(Vec2::new(available_width, desired_height), Sense::hover());
            let painter = ui.painter();

            painter.rect_filled(rect, 0.0, Color32::from_rgb(30, 30, 40));

            painter.rect_stroke(
                rect,
                0.0,
                Stroke::new(1.0, Color32::from_gray(80)),
                StrokeKind::Outside,
            );

            let progress_rect = Rect::from_min_max(
                rect.min,
                pos2(rect.min.x + fraction * rect.width(), rect.max.y),
            );

            let progress_color = Color32::from_rgb(
                (50 + (100.0 * fraction) as u8).min(150),
                180,
                (100 + (155.0 * fraction) as u8).min(255),
            );

            painter.rect_filled(progress_rect, 0.0, progress_color);

            let percent_text = format!("{:.1}%", progress.percent());

            painter.text(
                rect.center(),
                Align2::CENTER_CENTER,
                percent_text,
                FontId::monospace(12.0),
                Color32::WHITE,
            );

            if response.hovered() {
                let tooltip_rect = Rect::from_center_size(
                    rect.center_bottom() + vec2(0.0, 25.0),
                    Vec2::new(180.0, 40.0),
                );

                painter.rect_filled(tooltip_rect, 2.0, Color32::from_rgb(20, 20, 30));

                painter.rect_stroke(
                    tooltip_rect,
                    2.0,
                    Stroke::new(1.0, Color32::from_gray(70)),
                    StrokeKind::Outside,
                );

                let info_text = format!(
                    "{}/{} bytes\n{:.1}% complete",
                    progress.sent,
                    progress.total,
                    progress.percent()
                );

                painter.text(
                    tooltip_rect.center_top() + vec2(0.0, 8.0),
                    Align2::CENTER_TOP,
                    &info_text,
                    FontId::monospace(11.0),
                    Color32::from_gray(220),
                );
            }
        });

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Sent:")
                    .monospace()
                    .color(Color32::from_gray(150)),
            );
            ui.add_space(5.0);
            ui.label(
                RichText::new(format!("{} bytes", progress.sent))
                    .monospace()
                    .color(Color32::WHITE),
            );

            ui.add_space(10.0);

            ui.label(
                RichText::new("Total:")
                    .monospace()
                    .color(Color32::from_gray(150)),
            );
            ui.add_space(5.0);
            ui.label(
                RichText::new(format!("{} bytes", progress.total))
                    .monospace()
                    .color(Color32::WHITE),
            );

            ui.add_space(10.0);

            ui.label(
                RichText::new("Remaining:")
                    .monospace()
                    .color(Color32::from_gray(150)),
            );
            ui.add_space(5.0);
            ui.label(
                RichText::new(format!("{} bytes", progress.total - progress.sent as u64))
                    .monospace()
                    .color(Color32::WHITE),
            );
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            let pause_btn = ui.add(
                Button::new(RichText::new("[⏸ PAUSE]").monospace())
                    .fill(Color32::from_rgb(30, 30, 40))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(200, 150, 100)))
                    .corner_radius(2.0),
            );

            ui.add_space(10.0);

            let resume_btn = ui.add(
                Button::new(RichText::new("[▶ RESUME]").monospace())
                    .fill(Color32::from_rgb(30, 30, 40))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(100, 180, 100)))
                    .corner_radius(2.0),
            );

            if pause_btn.clicked() {
                let _ = cmd_tx.send(Command::Pause);
                let (lock, cond_var) = &**condvar;
                let mut state = lock.lock().unwrap();
                state.pause = true;
                cond_var.notify_all();
            }

            if resume_btn.clicked() {
                let (lock, cond_var) = &**condvar;
                let mut state = lock.lock().unwrap();
                state.pause = false;
                cond_var.notify_all();
            }
        });

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            let status_text = if fraction >= 1.0 {
                "[COMPLETED]"
            } else {
                "[TRANSFERRING]"
            };

            let status_color = if fraction >= 1.0 {
                Color32::from_rgb(100, 200, 100)
            } else {
                Color32::from_rgb(200, 180, 80)
            };

            ui.label(RichText::new(status_text).monospace().color(status_color));
            ui.label(
                RichText::new(" • ")
                    .monospace()
                    .color(Color32::from_gray(100)),
            );
            ui.label(
                RichText::new(format!("{:.1}% complete", progress.percent()))
                    .monospace()
                    .color(Color32::from_gray(150)),
            );
        });
    });
}

#[derive(Default, Clone)]
pub struct CancelConfirm {
    pub open: bool,
}

fn cancel_transfer_popup_command_style(
    ctx: &egui::Context,
    confirm: &mut CancelConfirm,
    is_sending: bool,
    mode: &mut Mode,
    condvar: &Arc<(Mutex<CondState>, Condvar)>,
    on_confirm_cancel: impl FnOnce(),
) {
    if !confirm.open {
        return;
    }

    let action = if is_sending { "sending" } else { "receiving" };
    let cur_mode = if is_sending {
        Mode::Send
    } else {
        Mode::Receive
    };

    egui::Window::new("")
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .frame(
            egui::Frame::popup(&ctx.style())
                .corner_radius(2.0)
                .inner_margin(egui::Margin::same(12))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(60))),
        )
        .show(ctx, |ui| {
            ui.set_width(360.0);

            ui.label(
                egui::RichText::new(format!("> cancel {}", action))
                    .monospace()
                    .strong(),
            );

            ui.add_space(8.0);

            ui.label(egui::RichText::new("This will abort the current transfer.").monospace());
            ui.label(
                egui::RichText::new("warning: partial data will be discarded")
                    .monospace()
                    .color(egui::Color32::from_rgb(180, 140, 80)),
            );

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                let continue_btn = ui.add(egui::Button::new(
                    egui::RichText::new("[ continue ]").monospace(),
                ));

                let cancel_btn = ui.add(egui::Button::new(
                    egui::RichText::new("[ cancel ]")
                        .monospace()
                        .color(egui::Color32::from_rgb(200, 90, 90)),
                ));

                if continue_btn.clicked() {
                    confirm.open = false;
                    *mode = cur_mode;
                }

                if cancel_btn.clicked() {
                    let (lock, condvar) = &**condvar;
                    let mut state = lock.lock().unwrap();
                    state.error = true;
                    condvar.notify_all();

                    confirm.open = false;
                    on_confirm_cancel();
                    *mode = Mode::Idle;

                }
            });

            if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                confirm.open = false;
            }
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

    let hash = if let Some(hash) = file_hash.hash {
        format!("{}", hash)
    } else {
        "Computing Hash..".to_string()
    };

    let mut window_open = true;
    egui::Window::new("")
        .open(&mut window_open)
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .frame(
            egui::Frame::popup(&ctx.style())
                .corner_radius(2.0)
                .inner_margin(egui::Margin::same(20))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(60)))
                .fill(egui::Color32::from_rgb(15, 15, 20)),
        )
        .show(ctx, |ui| {
            ui.set_width(400.0);

            ui.horizontal(|ui| {
                ui.colored_label(accent, "> ");
                ui.label(
                    egui::RichText::new("INCOMING FILE")
                        .color(accent)
                        .monospace()
                        .strong(),
                );
            });

            ui.add_space(15.0);
            ui.separator();
            ui.add_space(15.0);

            if let Some(metadata) = metadata {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("File Information")
                                .color(accent)
                                .monospace()
                                .strong(),
                        );
                    });

                    ui.add_space(10.0);

                    Grid::new("recv_file_popup_grid")
                        .spacing([15.0, 6.0])
                        .show(ui, |ui| {
                            terminal_grid_row(ui, "Name:", &metadata.name);
                            terminal_grid_row(ui, "Size:", &metadata.size);
                            terminal_grid_row(ui, "Type:", &metadata.file_type);
                            terminal_grid_row(ui, "Path:", &metadata.path);
                        });
                });

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(20.0);

                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("File Verification")
                                .color(accent)
                                .monospace()
                                .strong(),
                        );
                    });

                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("Hash Algorithm:")
                                .monospace()
                                .color(egui::Color32::from_gray(150)),
                        );
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("BLAKE3")
                                .monospace()
                                .color(egui::Color32::from_rgb(100, 180, 100)),
                        );
                    });

                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("Hash Value:")
                                .monospace()
                                .color(egui::Color32::from_gray(150)),
                        );
                    });

                    ui.add_space(4.0);

                    let hash_frame = egui::Frame::new()
                        .fill(egui::Color32::from_rgb(25, 25, 30))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(70)))
                        .inner_margin(egui::Margin::symmetric(12, 8));

                    hash_frame.show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(&hash)
                                .monospace()
                                .color(egui::Color32::from_rgb(180, 180, 220))
                                .size(12.0),
                        );
                    });
                });

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(20.0);

                ui.horizontal(|ui| {
                    let cancel_btn = ui.add(
                        egui::Button::new(
                            egui::RichText::new("[ REJECT ]")
                                .monospace()
                                .color(egui::Color32::from_rgb(200, 90, 90)),
                        )
                        .fill(egui::Color32::from_rgb(30, 20, 25))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(200, 90, 90)))
                        .corner_radius(2.0),
                    );

                    ui.add_space(20.0);

                    let accept_btn = ui.add(
                        egui::Button::new(
                            egui::RichText::new("[ ACCEPT ]")
                                .monospace()
                                .color(egui::Color32::from_rgb(100, 200, 100)),
                        )
                        .fill(egui::Color32::from_rgb(20, 30, 25))
                        .stroke(egui::Stroke::new(
                            1.0,
                            egui::Color32::from_rgb(100, 200, 100),
                        ))
                        .corner_radius(2.0),
                    );

                    if cancel_btn.clicked() {
                        let _ = cmd_tx.send(Command::Decision(Decision::Reject));
                        *mode = Mode::Idle;
                    }

                    if accept_btn.clicked() {
                        let _ = cmd_tx.send(Command::Decision(Decision::Accept));
                    }
                });
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(30.0);
                    ui.label(
                        egui::RichText::new("Waiting for file metadata...")
                            .monospace()
                            .color(egui::Color32::from_gray(150)),
                    );

                    ui.add_space(20.0);

                    ui.horizontal_centered(|ui| {
                        let dots = match (ctx.input(|i| i.time) * 2.0) as usize % 4 {
                            0 => "   ",
                            1 => ".  ",
                            2 => ".. ",
                            _ => "...",
                        };
                        ui.label(
                            egui::RichText::new(format!("[CONNECTING{}]", dots))
                                .monospace()
                                .color(accent),
                        );
                    });
                });

                ui.add_space(15.0);
                ui.separator();
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("[CONNECTING]")
                            .monospace()
                            .color(egui::Color32::from_rgb(200, 180, 80)),
                    );
                    ui.label(
                        egui::RichText::new(" • ")
                            .monospace()
                            .color(egui::Color32::from_gray(100)),
                    );
                    ui.label(
                        egui::RichText::new("Establishing connection")
                            .monospace()
                            .color(egui::Color32::from_gray(150)),
                    );
                });
            }
        });

    if !window_open {
        let _ = cmd_tx.send(Command::Decision(Decision::Reject));
        *mode = Mode::Idle;
    }
}

fn terminal_grid_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(
        egui::RichText::new(label)
            .monospace()
            .color(egui::Color32::from_gray(150)),
    );
    ui.label(egui::RichText::new(value).monospace());
    ui.end_row();
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
    is_expanded: &mut bool,
) {
    let accent = Color32::from_rgb(180, 100, 255);
    let status_frame = egui::Frame::window(&ui.style())
        .fill(Color32::from_rgb(15, 15, 20))
        .stroke(Stroke::new(1.0, Color32::from_gray(60)))
        .inner_margin(Margin::same(20))
        .corner_radius(2.0);

    status_frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("> [STATUS]")
                    .monospace()
                    .strong()
                    .color(accent),
            );
        });
        ui.add_space(8.0);

        if let Some(state) = handshake_state {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;

                let steps = [
                    ("Initialized", ReceiveHandShakeState::Initialized),
                    ("Public Key Sent", ReceiveHandShakeState::PublicKeySent),
                    ("Public Key Received", ReceiveHandShakeState::PublicKeyReceived),
                    ("Shared Secret", ReceiveHandShakeState::DeriveSharedSecret),
                    ("Transcript", ReceiveHandShakeState::DeriveTranscript),
                ];

                for (i, (label, step)) in steps.iter().enumerate() {
                    let is_active = state == step;
                    let is_completed = state > step;

                    let color = if is_active {
                        accent
                    } else if is_completed {
                        accent.gamma_multiply(0.7)
                    } else {
                        Color32::from_gray(100)
                    };

                    ui.label(RichText::new(*label).monospace().color(color));

                    if i < steps.len() - 1 {
                        ui.colored_label(
                            if is_completed {
                                accent.gamma_multiply(0.7)
                            } else {
                                Color32::from_gray(80)
                            },
                            " › ",
                        );
                    }
                }

                if is_receiving || received {
                    ui.colored_label(Color32::from_gray(80), " › ");
                    ui.label(RichText::new("Receiving").monospace().color(if received {
                        accent.gamma_multiply(0.7)
                    } else {
                        accent
                    }));
                }

                if received {
                    ui.colored_label(Color32::from_gray(80), " › ");
                    ui.label(RichText::new("Completed").monospace().color(accent));
                }
            });
        } else {
            ui.label(
                RichText::new("Waiting for handshake initialization…")
                    .monospace()
                    .color(Color32::from_gray(120)),
            );
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(10.0);

        let lock_secret = is_receiving || received;

        if lock_secret && *is_expanded {
            *is_expanded = false;
        }

        ui.horizontal(|ui| {
            let arrow = if *is_expanded { "▼" } else { "▶" };

            let arrow_label = egui::Label::new(
                RichText::new(arrow).monospace().color(if lock_secret {
                    Color32::from_gray(90)
                } else {
                    accent
                }),
            );

            let arrow_resp = if lock_secret {
                ui.add(arrow_label)
            } else {
                ui.add(arrow_label.sense(egui::Sense::click()))
            };

            ui.label(
                RichText::new("SECRET")
                    .monospace()
                    .strong()
                    .color(if lock_secret {
                        Color32::from_gray(90)
                    } else {
                        accent
                    }),
            );

            if !*is_expanded {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(if lock_secret {
                        "(collapsed during transfer)"
                    } else {
                        "(click to enter secret code)"
                    })
                    .monospace()
                    .color(Color32::from_gray(120)),
                );
            }

            if arrow_resp.clicked() && !*is_expanded {
                *is_expanded = !*is_expanded;
            }
        });

        if *is_expanded {
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Code:")
                        .monospace()
                        .color(Color32::from_gray(150)),
                );

                ui.add(
                    TextEdit::singleline(secret)
                        .font(FontId::monospace(18.0))
                        .desired_width(ui.available_width()) 
                        .interactive(true)
                        .hint_text(
                            "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX",
                        ),
                );
            });

            ui.add_space(12.0);

            ui.horizontal(|ui| {
                let auth_btn = ui.add(
                    egui::Button::new(
                        RichText::new("[ AUTHENTICATE ]")
                            .monospace()
                            .color(Color32::from_rgb(180, 220, 255)),
                    )
                    .fill(Color32::from_rgb(20, 25, 30))
                    .stroke(Stroke::new(1.0, accent))
                    .corner_radius(2.0),
                );

                if auth_btn.clicked() {
                    let _ = cmd_tx.send(Command::StartReciver {
                        code: secret.clone(),
                    });
                }
            });
        }
    });
}

fn receiver_card_single_box(
    ui: &mut Ui,
    save_location: &mut String,
    cmd_tx: &Sender<Command>,
    metadata: &Option<FileMetadata>,
    file_hash: &FileHash,
    sender_data: Option<SenderNetworkInfo>,
    receiver_data: Option<ReceiverNetworkInfo>,
    ctx: &Context,
) {
    let accent = Color32::from_rgb(180, 100, 255);

    let outer_frame = Frame::window(&ui.style())
        .fill(Color32::from_rgb(15, 15, 20))
        .stroke(Stroke::new(1.0, Color32::from_gray(60)))
        .inner_margin(Margin::same(20))
        .corner_radius(2.0);

    outer_frame.show(ui, |ui| {
        ui.set_min_width(ui.available_width());

        ui.horizontal(|ui| {
            ui.colored_label(accent, "> ");
            ui.label(
                RichText::new("[OVERVIEW]")
                    .color(accent)
                    .monospace()
                    .strong(),
            );
        });

        ui.add_space(15.0);

        let hash = if let Some(h) = file_hash.hash {
            format!("{h}")
        } else {
            "Computing hash…".to_string()
        };

        let available = ui.available_width();

        match metadata {
            Some(data) => {
                if available >= 1920.0 {
                    ui.horizontal_centered(|ui| {
                        ui.vertical(|ui| {
                            file_info_box(ui, accent, data, &hash);
                        });

                                ui.add_space(50.0);


                        if let (Some(sender), Some(receiver)) =
                            (sender_data.as_ref(), receiver_data.as_ref())
                        {
                            ui.vertical(|ui| {
                                receive_network_box(ui, accent, sender, receiver);
                            });
                        }

                        ui.add_space(50.0);
                    });
                } else if available >= 1000.0 {
                    ui.horizontal_centered(|ui| {
                        ui.vertical(|ui| {
                            file_info_box(ui, accent, data, &hash);
                        });

                            ui.add_space(50.0);

                        if let (Some(sender), Some(receiver)) =
                            (sender_data.as_ref(), receiver_data.as_ref())
                        {
                            ui.vertical(|ui| {
                                receive_network_box(ui, accent, sender, receiver);
                            });
                        }
                    });
                } else {
                    ui.vertical_centered(|ui| {
                        file_info_box(ui, accent, data, &hash);

                        ui.add_space(50.0);

                        if let (Some(sender), Some(receiver)) =
                            (sender_data.as_ref(), receiver_data.as_ref())
                        {
                            receive_network_box(ui, accent, sender, receiver);
                        }

                        ui.add_space(50.0);

                    });
                }
            }

            None => {
                ui.label(
                    RichText::new("Waiting for file metadata…")
                        .monospace()
                        .color(Color32::from_gray(120)),
                );
            }
        }
    });
}

fn receive_network_box(
    ui: &mut Ui,
    accent: Color32,
    sender: &SenderNetworkInfo,
    receiver: &ReceiverNetworkInfo,
) {
    ui.set_min_width(260.0);

    ui.horizontal(|ui| {
        ui.label(RichText::new("NETWORK").monospace().strong().color(accent));
    });

    ui.add_space(8.0);

    let frame = egui::Frame::new()
        .fill(Color32::from_rgb(25, 25, 30))
        .stroke(Stroke::new(1.0, Color32::from_gray(70)))
        .inner_margin(Margin::symmetric(10, 10))
        .corner_radius(2.0);

    frame.show(ui, |ui| {
        terminal_kv(ui, "Public IP", &sender.ip);
        terminal_kv(ui, "Port", &sender.port);
        terminal_kv(ui, "Peer IP", &receiver.ip);
        terminal_kv(ui, "Peer Port", &receiver.port);
        terminal_kv(ui, "Transport", "TCP");
        terminal_kv(ui, "Role", "Receiver");
    });
}

fn terminal_kv(ui: &mut Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{key}:"))
                .monospace()
                .color(Color32::from_gray(150)),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new(value)
                .monospace()
                .color(Color32::from_gray(220)),
        );
    });
}

fn error_popup(ctx: &egui::Context, error: &mut Option<UiError>, mode: &mut Mode, condvar: &Arc<(Mutex<CondState>, Condvar)>) {
    let Some(err) = error else { return };
    let err = err.clone();

    let accent = egui::Color32::from_rgb(200, 90, 90);

    let mut window_open = true;
    egui::Window::new("")
        .open(&mut window_open)
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .frame(
            egui::Frame::popup(&ctx.style())
                .corner_radius(2.0)
                .inner_margin(egui::Margin::same(20))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(60)))
                .fill(egui::Color32::from_rgb(15, 15, 20)),
        )
        .show(ctx, |ui| {
            ui.set_width(400.0);

            ui.horizontal(|ui| {
                ui.colored_label(accent, "> ");
                ui.label(
                    egui::RichText::new("ERROR")
                        .color(accent)
                        .monospace()
                        .strong(),
                );
            });

            ui.add_space(15.0);
            ui.separator();
            ui.add_space(15.0);

            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(err.title())
                        .monospace()
                        .color(egui::Color32::from_gray(220)),
                );

                if let Some(details) = err.details() {
                    ui.add_space(8.0);

                    let details_frame = egui::Frame::new()
                        .fill(egui::Color32::from_rgb(25, 25, 30))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(70)))
                        .inner_margin(egui::Margin::symmetric(12, 8));

                    details_frame.show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(details)
                                .monospace()
                                .size(12.0)
                                .color(egui::Color32::from_gray(160)),
                        );
                    });
                }
            });

            ui.add_space(20.0);
            ui.separator();
            ui.add_space(20.0);

            ui.horizontal(|ui| {
                let ok_btn = ui.add(
                    egui::Button::new(
                        egui::RichText::new("[ OK ]")
                            .monospace()
                            .color(egui::Color32::from_rgb(180, 180, 180)),
                    )
                    .fill(egui::Color32::from_rgb(25, 25, 30))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(120)))
                    .corner_radius(2.0),
                );

                if ok_btn.clicked() {
                    let (lock, state) = &**condvar;
                    let mut lock = lock.lock().unwrap();
                    lock.error = true;
                    state.notify_all();

                    *error = None;
                    *mode = Mode::Idle;
                }
            });
        });

    if !window_open {
        *error = None;
        *mode = Mode::Idle;
    }
}

fn top_bar(
    ui: &mut egui::Ui,
    color: egui::Color32,
    mode: &mut Mode,
    cmd_tx: &Sender<Command>,
) -> bool {
    let mut home_button_clicked = false;

    egui::Frame::new().show(ui, |ui| {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if home_button(ui).clicked() {
                home_button_clicked = true;
            }

            let (bar_rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 24.0), egui::Sense::hover());
            ui.painter().rect_filled(bar_rect, 2.0, color);
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

fn receiver_cancelled_popup(
    ctx: &egui::Context,
    is_declined: &mut bool,
    mode: &mut Mode,
) {
    if !*is_declined {
        return;
    }

    let accent = egui::Color32::from_rgb(180, 100, 255);
    let mut window_open = true;

    egui::Window::new("")
        .open(&mut window_open)
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .frame(
            egui::Frame::popup(&ctx.style())
                .corner_radius(2.0)
                .inner_margin(egui::Margin::same(20))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(60)))
                .fill(egui::Color32::from_rgb(15, 15, 20)),
        )
        .show(ctx, |ui| {
            ui.set_width(420.0);

            ui.horizontal(|ui| {
                ui.colored_label(accent, "> ");
                ui.label(
                    egui::RichText::new("TRANSFER CANCELLED")
                        .color(accent)
                        .monospace()
                        .strong(),
                );
            });

            ui.add_space(15.0);
            ui.separator();
            ui.add_space(15.0);

            ui.label(
                egui::RichText::new(
                    "The receiver has cancelled the file transfer.",
                )
                .monospace()
                .color(egui::Color32::from_gray(220)),
            );

            ui.add_space(20.0);
            ui.separator();
            ui.add_space(20.0);

            // Action
            ui.horizontal(|ui| {
                let ok_btn = ui.add(
                    egui::Button::new(
                        egui::RichText::new("[ OK ]")
                            .monospace()
                            .color(egui::Color32::from_rgb(180, 180, 180)),
                    )
                    .fill(egui::Color32::from_rgb(25, 25, 30))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(120)))
                    .corner_radius(2.0),
                );

                if ok_btn.clicked() {
                    *is_declined = false;
                    *mode = Mode::Idle;
                }
            });
        });

    if !window_open {
        *is_declined = false;
        *mode = Mode::Idle;
    }
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
