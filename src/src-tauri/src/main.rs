#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Error;
use app_lib::{
    crypto,
    handshake::{self, encode},
};
use std::{
    env::Args,
    fs::File,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket},
    str::FromStr,
};
use tauri::menu::{MenuBuilder, PredefinedMenuItem};
use x25519_dalek::PublicKey;

fn main() {
    // let human_readable_code = encode(socket_addr).unwrap();
    //
    // handshake::test(socket_addr, human_readable_code).unwrap();
}
