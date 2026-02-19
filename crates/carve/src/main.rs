use std::env;
use std::fs;
use std::process;

use carve_core::jpeg::parse::{parse_until_sos, ParseError};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: carve <file.jpg>");
        process::exit(1);
    }

    let path = &args[1];
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading '{}': {}", path, e);
            process::exit(1);
        }
    };

    println!("Parsing: {} ({:.1} KB)", path, bytes.len() as f64 / 1024.0);
    println!();

    // Allow up to 64 MB for the pre-SOS header scan
    let max_scan = 64 * 1024 * 1024;

    match parse_until_sos(&bytes, 0, max_scan) {
        Ok(result) => {
            println!("SOS marker at: byte {}", result.sos_marker_pos);
            println!("Scan starts at: byte {}", result.scan_start);
            println!("Segments parsed: {}", result.segments_parsed);

            match (result.width, result.height) {
                (Some(w), Some(h)) => println!("Dimensions: {} x {}", w, h),
                _ => println!("Dimensions: (not found)"),
            }

            match result.is_progressive {
                Some(true)  => println!("Progressive: yes"),
                Some(false) => println!("Progressive: no"),
                None        => println!("Progressive: (unknown)"),
            }

            println!("Has DQT: {}", if result.has_dqt { "yes" } else { "no" });
            println!("Has DHT: {}", if result.has_dht { "yes" } else { "no" });
            println!("Has Exif: {}", if result.has_exif { "yes" } else { "no" });

            println!();
            println!("Parse successful");
        }
        Err(e) => {
            let msg = match &e {
                ParseError::OutOfBounds => "read past end of file".to_string(),
                ParseError::NotJpeg => "not a JPEG (missing SOI marker)".to_string(),
                ParseError::MissingSos => "no SOS marker found".to_string(),
                ParseError::InvalidMarkerStream { at } =>
                    format!("invalid marker stream at byte {}", at),
                ParseError::InvalidSegmentLength { at, len } =>
                    format!("invalid segment length {} at byte {}", len, at),
                ParseError::SegmentLengthOverflows { at, len } =>
                    format!("segment length {} overflows file at byte {}", len, at),
                ParseError::BadSofPayload { at } =>
                    format!("bad SOF payload at byte {}", at),
            };
            eprintln!("Parse failed: {}", msg);
            process::exit(1);
        }
    }
}
