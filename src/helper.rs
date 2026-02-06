use crate::state::FileMetadata;
use anyhow::{Error, Result};
use blake3::Hash;
use std::fmt::Write;
use std::net::{SocketAddr, UdpSocket};
use std::{fs::File, io::Read, path::PathBuf};

const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
pub const PREHASH_LIMIT: u64 = 5 * 1024 * 1024 * 1024; // 5 gig hard limit for prehashing.

pub fn get_file_size(bytes: u64) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut unit = 0;
    let mut value = bytes as f64;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    let mut out = String::new();
    if value >= 10.0 {
        write!(out, "{:.0} {}", value, UNITS[unit]).unwrap();
    } else {
        write!(out, "{:.1} {}", value, UNITS[unit]).unwrap();
    }
    out
}

pub fn get_file_hash(file: &mut File) -> Result<Hash, Error> {
    let mut buf = [0u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new();

    while let Ok(n) = file.read(&mut buf) {
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize())
}

use chrono::{DateTime, Local};

pub fn get_file_metadata(file: &File, file_path: &PathBuf) -> Result<FileMetadata, Error> {
    let metadata = file.metadata()?;

    let file_name = file_path
        .file_name()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_owned();

    let file_type = if let Some(file_type) = infer::get_from_path(file_path)? {
        file_type.mime_type().to_string()
    } else {
        String::from("Unknown")
    };

    let file_path = file_path.to_str().unwrap_or_default().to_owned();
    let file_size = get_file_size(metadata.len());
    let modified_date = metadata.modified().ok();
    let raw_file_size = metadata.len();

    let modified_date = if let Some(modified) = modified_date {
        match modified.elapsed() {
            Ok(elapsed) => {
                if elapsed.as_secs() >= 86_400 {
                    let dt: DateTime<Local> = modified.into();
                    dt.format("%Y-%m-%d").to_string()
                } else {
                    let secs = elapsed.as_secs();
                    format!(
                        "{:02}:{:02}:{:02}",
                        secs / 3600,
                        (secs % 3600) / 60,
                        secs % 60
                    )
                }
            }
            Err(_) => "Unknown".into(),
        }
    } else {
        "Unknown".into()
    };

    let file_metadata = FileMetadata {
        name: file_name,
        size: file_size,
        raw_bytes: raw_file_size,
        file_type,
        path: file_path,
        modified_date,
    };

    Ok(file_metadata)
}

pub fn get_socket_addr() -> Result<SocketAddr, Error> {
    let remote: SocketAddr = "[2606:4700:4700::1111]:53"
        .parse()
        .expect("Failed to parse Ipv6");

    let socket = UdpSocket::bind("[::]:0")?;
    socket.connect(remote)?;

    Ok(socket.local_addr()?)
}
