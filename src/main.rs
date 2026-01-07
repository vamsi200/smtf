#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use anyhow::Error;
use eframe::{Frame, NativeOptions};
use egui::{Context, FontData, FontDefinitions, Grid, Stroke};
use rfd::FileDialog;
use smtf::{
    handshake::{self, *},
    helper,
    state::{self, FileMetadata},
    ui,
};
use std::{
    env::{self, Args},
    fs::File,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    str::FromStr,
};
use x25519_dalek::PublicKey;

use std::time::{Duration, Instant};

fn main() -> Result<(), Error> {
    env_logger::init();
    let cwd = env::current_dir().expect("Failed to get current directory!");
    let Some(file) = FileDialog::new().set_directory(cwd).pick_file() else {
        println!("No file selected");
        return Ok(());
    };

    let s = helper::get_file_state(file)?;
    println!("State: {s:#?}");
    Ok(())
}

fn entry_point() {
    todo!()
}
