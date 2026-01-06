#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use anyhow::Error;
use smtf::handshake::{self, *};
use std::{
    env::Args,
    fs::File,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket},
    str::FromStr,
};
use x25519_dalek::PublicKey;

fn main() {

    // let human_readable_code = encode(socket_addr).unwrap();
    //
    // handshake::test(socket_addr, human_readable_code).unwrap();
}
