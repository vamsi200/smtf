use crate::state::{FileMetadata, FileState};
use anyhow::{Error, Result};
use log::log;
use std::fmt::Write;
use std::{fs::File, io::Read, path::PathBuf};

const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

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

pub fn get_file_state(file_path: PathBuf) -> Result<FileState, Error> {
    log!(
        log::Level::Info,
        "Getting File Metadata - {}",
        file_path.display()
    );

    let mut file = File::open(file_path.clone())?;
    let mut buf = [0u8; 64 * 1024];
    let metadata = file.metadata()?;

    let mut hasher = blake3::Hasher::new();

    let mut file_type = String::new();

    let file_name = file_path
        .file_name()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_owned();

    log!(log::Level::Info, "Calculating File Hash");

    while let Ok(n) = file.read(&mut buf) {
        if n == 0 {
            break;
        }
        hasher.update(&mut buf);
        file_type = infer::get(&buf[..n])
            .map(|t| t.mime_type().to_string())
            .unwrap_or(String::from("Unknown Type"));
    }

    let hash = hasher.finalize().to_string();
    let file_path = file_path.to_str().unwrap_or_default().to_owned();
    let file_size = get_file_size(metadata.len());

    let file_metadata = FileMetadata {
        name: file_name,
        size: file_size,
        file_type: file_type,
        path: file_path,
        hash: hash,
    };

    Ok(FileState::FileSelected(file_metadata))
}
