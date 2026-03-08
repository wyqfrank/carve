use std::env;
use std::fs;
use std::process;

use carve_core::jpeg::parse::{parse_until_sos, ParseError};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliOptions {
    file_path: String,
    keep_overlaps: bool,
}

fn parse_args(args: &[String]) -> Result<CliOptions, String> {
    if args.len() < 2 {
        return Err("Usage: carve [--keep-overlaps] <file.jpg>".to_string());
    }

    let mut keep_overlaps = false;
    let mut file_path: Option<String> = None;

    for arg in &args[1..] {
        match arg.as_str() {
            "--keep-overlaps" => keep_overlaps = true,
            _ if arg.starts_with('-') => {
                return Err(format!("Unknown flag: {arg}\nUsage: carve [--keep-overlaps] <file.jpg>"));
            }
            _ => {
                if file_path.is_some() {
                    return Err("Only one input file is supported.\nUsage: carve [--keep-overlaps] <file.jpg>".to_string());
                }
                file_path = Some(arg.clone());
            }
        }
    }

    match file_path {
        Some(path) => Ok(CliOptions {
            file_path: path,
            keep_overlaps,
        }),
        None => Err("Missing input file.\nUsage: carve [--keep-overlaps] <file.jpg>".to_string()),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let options = match parse_args(&args) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}");
            process::exit(1);
        }
    };

    let path = &options.file_path;
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading '{}': {}", path, e);
            process::exit(1);
        }
    };

    println!("Parsing: {} ({:.1} KB)", path, bytes.len() as f64 / 1024.0);
    println!(
        "Keep overlaps: {}",
        if options.keep_overlaps { "enabled" } else { "disabled" }
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parses_without_flag() {
        let parsed = parse_args(&args(&["carve", "image.jpg"])).unwrap();
        assert_eq!(parsed.file_path, "image.jpg");
        assert!(!parsed.keep_overlaps);
    }

    #[test]
    fn parses_keep_overlaps_flag() {
        let parsed = parse_args(&args(&["carve", "--keep-overlaps", "image.jpg"])).unwrap();
        assert_eq!(parsed.file_path, "image.jpg");
        assert!(parsed.keep_overlaps);
    }

    #[test]
    fn rejects_unknown_flag() {
        let err = parse_args(&args(&["carve", "--bad-flag", "image.jpg"])).unwrap_err();
        assert!(err.contains("Unknown flag"));
    }
}
