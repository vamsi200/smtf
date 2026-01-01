#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Error;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket},
};

fn main() {
    // app_lib::run();
    test().expect("error");
}

fn handle_stream(mut stream: TcpStream) -> Result<(), Error> {
    let mut buffer = Vec::new();
    let mut response = [0u8; 1024];

    loop {
        let n = stream.read(&mut response)?;
        if n == 0 {
            break;
        }

        buffer.extend_from_slice(&response[..n]);

        while let Some(pos) = buffer.iter().position(|&x| x == b'\n') {
            let msg = buffer[..pos].to_vec();
            buffer.drain(..=pos);
            let string = str::from_utf8(&msg)?;
            println!("Response - {string}");
        }
    }

    // if response.contains(&new_line) && response.contains(&content) {
    //     stream.write_fmt(format_args!("Hello, how are you!\n"))?;
    // } else {
    //     stream.shutdown(std::net::Shutdown::Both)?;
    // }
    Ok(())
}

fn generate_token(ip: SocketAddr) -> Result<String, Error> {
    let ip_bytes = format!("{ip}").as_bytes().to_owned();
    Ok(base32::encode(base32::Alphabet::Crockford, &ip_bytes))
}

fn test() -> Result<(), Error> {
    use base32;

    // let listener = TcpListener::bind("[::]:36679")?;
    let udp_sock = UdpSocket::bind("[::]:36679")?;
    udp_sock.connect("[2606:4700:4700::1111]:80")?;
    let socket_addr = udp_sock.local_addr()?;

    let encoded_ip = generate_token(socket_addr)?;
    println!("Encoded IP - {encoded_ip}");
    let decode = base32::decode(base32::Alphabet::Crockford, &encoded_ip).unwrap();
    println!("Decoded IP - {}", str::from_utf8(&decode).unwrap());

    // println!(
    //     "Listener started - {}",
    //     listener
    //         .local_addr()
    //         .expect("Failed to get listener address")
    // );
    //
    // if let Ok(conn) = listener.accept() {
    //     println!("New Connection: {}", conn.1);
    //     let stream = conn.0;
    //     handle_stream(stream).expect("Error");
    // }
    //
    Ok(())
}
