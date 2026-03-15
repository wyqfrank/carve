use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use carve_core::extract::extract_candidates;
use carve_core::jpeg::marker_dump::dump_jpeg_segments;
use carve_core::jpeg::validate::{PatchEoiPolicy, ValidationOptions};
use carve_core::report::write_report;
use carve_core::scanner::{apply_validated_overlap_policy, recover_candidates, OverlapOptions};

const USAGE: &str = "\
Usage:
  carve [--keep-overlaps] <file|pattern> [<file|pattern> ...]
  carve --dump [--json] <file>

Flags:
  --keep-overlaps   Emit all candidates without overlap suppression
  --dump            Print JPEG segment structure instead of carving
  --json            With --dump: output JSON instead of a text table";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliOptions {
    file_paths: Vec<String>,
    keep_overlaps: bool,
    dump: bool,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<CliOptions, String> {
    if args.len() < 2 {
        return Err(USAGE.to_string());
    }

    let mut keep_overlaps = false;
    let mut dump = false;
    let mut json = false;
    let mut file_paths: Vec<String> = Vec::new();

    for arg in &args[1..] {
        match arg.as_str() {
            "--keep-overlaps" => keep_overlaps = true,
            "--dump" => dump = true,
            "--json" => json = true,
            _ if arg.starts_with('-') => {
                return Err(format!("Unknown flag: {arg}\n{USAGE}"));
            }
            _ => {
                // If the argument contains glob characters, expand it;
                // otherwise treat it as a literal file path.
                if arg.contains('*') || arg.contains('?') || arg.contains('[') {
                    let mut matches: Vec<String> = glob::glob(arg)
                        .map_err(|e| format!("Invalid pattern '{arg}': {e}"))?
                        .filter_map(|entry| entry.ok())
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect();
                    matches.sort();
                    if matches.is_empty() {
                        return Err(format!("No files matched pattern: {arg}"));
                    }
                    file_paths.extend(matches);
                } else {
                    file_paths.push(arg.clone());
                }
            }
        }
    }

    if file_paths.is_empty() {
        return Err(format!("Missing input file.\n{USAGE}"));
    }

    Ok(CliOptions {
        file_paths,
        keep_overlaps,
        dump,
        json,
    })
}

fn output_dir_for(input: &str) -> PathBuf {
    let stem = Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    PathBuf::from("recovered").join(stem)
}

/// Read and concatenate all input files into a single byte buffer.
fn read_inputs(paths: &[String]) -> Result<Vec<u8>, (String, std::io::Error)> {
    let mut bytes = Vec::new();
    for path in paths {
        let data = fs::read(path).map_err(|e| (path.clone(), e))?;
        bytes.extend_from_slice(&data);
    }
    Ok(bytes)
}

fn run_dump(cli: &CliOptions, bytes: &[u8]) {
    match dump_jpeg_segments(bytes, 0) {
        Ok(dump) => {
            if cli.json {
                println!("{}", dump.to_json());
            } else {
                println!("JPEG segment dump: {}", cli.file_paths[0]);
                print!("{}", dump.to_debug_text());
            }
        }
        Err(e) => {
            eprintln!("Failed to parse JPEG segments: {:?}", e);
            process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let cli = match parse_args(&args) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}");
            process::exit(1);
        }
    };

    let bytes = match read_inputs(&cli.file_paths) {
        Ok(b) => b,
        Err((path, e)) => {
            eprintln!("Error reading '{}': {}", path, e);
            process::exit(1);
        }
    };

    if cli.dump {
        run_dump(&cli, &bytes);
        return;
    }

    if cli.file_paths.len() == 1 {
        println!(
            "Scanning: {} ({:.1} KB)",
            cli.file_paths[0],
            bytes.len() as f64 / 1024.0
        );
    } else {
        println!(
            "Scanning: {} files concatenated ({:.1} KB total)",
            cli.file_paths.len(),
            bytes.len() as f64 / 1024.0
        );
    }

    let validation_options = ValidationOptions {
        allow_truncated: true,
        max_size: bytes.len(),
        patch_eoi: PatchEoiPolicy::Append,
    };

    let candidates = recover_candidates(&bytes, validation_options);
    let candidates = apply_validated_overlap_policy(
        candidates,
        OverlapOptions {
            keep_overlaps: cli.keep_overlaps,
        },
    );

    println!("Found {} candidate(s)", candidates.len());

    if candidates.is_empty() {
        println!("No JPEG candidates found.");
        return;
    }

    let out_dir = output_dir_for(&cli.file_paths[0]);
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("Failed to create output directory '{}': {}", out_dir.display(), e);
        process::exit(1);
    }

    match extract_candidates(&bytes, &candidates, &out_dir) {
        Ok(paths) => {
            for (i, path) in paths.iter().enumerate() {
                let c = &candidates[i];
                println!(
                    "  [{}] {} — start={} end={} status={:?} confidence={:.2}{}{}",
                    i,
                    path.display(),
                    c.start,
                    c.end,
                    c.status,
                    c.confidence_score,
                    if c.missing_soi { " (SOI synthesized)" } else { "" },
                    if c.patched_eoi { " (EOI patched)" } else { "" },
                );
            }
        }
        Err(e) => {
            eprintln!("Extraction failed: {}", e);
            process::exit(1);
        }
    }

    let report_path = out_dir.join("report.jsonl");
    if let Err(e) = write_report(&report_path, &candidates) {
        eprintln!("Failed to write report: {}", e);
        process::exit(1);
    }

    println!("Report: {}", report_path.display());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parses_single_file() {
        let parsed = parse_args(&args(&["carve", "image.jpg"])).unwrap();
        assert_eq!(parsed.file_paths, vec!["image.jpg"]);
        assert!(!parsed.keep_overlaps);
        assert!(!parsed.dump);
        assert!(!parsed.json);
    }

    #[test]
    fn parses_multiple_files() {
        let parsed = parse_args(&args(&["carve", "a.jpg", "b.jpg", "c.jpg"])).unwrap();
        assert_eq!(parsed.file_paths, vec!["a.jpg", "b.jpg", "c.jpg"]);
        assert!(!parsed.keep_overlaps);
    }

    #[test]
    fn parses_keep_overlaps_with_multiple_files() {
        let parsed = parse_args(&args(&["carve", "--keep-overlaps", "a.jpg", "b.jpg"])).unwrap();
        assert_eq!(parsed.file_paths, vec!["a.jpg", "b.jpg"]);
        assert!(parsed.keep_overlaps);
    }

    #[test]
    fn parses_dump_flag() {
        let parsed = parse_args(&args(&["carve", "--dump", "image.jpg"])).unwrap();
        assert!(parsed.dump);
        assert!(!parsed.json);
        assert_eq!(parsed.file_paths, vec!["image.jpg"]);
    }

    #[test]
    fn parses_dump_json_flags() {
        let parsed = parse_args(&args(&["carve", "--dump", "--json", "image.jpg"])).unwrap();
        assert!(parsed.dump);
        assert!(parsed.json);
    }

    #[test]
    fn rejects_unknown_flag() {
        let err = parse_args(&args(&["carve", "--bad-flag", "image.jpg"])).unwrap_err();
        assert!(err.contains("Unknown flag"));
    }

    #[test]
    fn rejects_no_files() {
        let err = parse_args(&args(&["carve"])).unwrap_err();
        assert!(err.contains("Usage"));
    }

    #[test]
    fn rejects_only_flag_no_file() {
        let err = parse_args(&args(&["carve", "--keep-overlaps"])).unwrap_err();
        assert!(err.contains("Missing input file"));
    }

    #[test]
    fn output_dir_derives_from_stem() {
        assert_eq!(output_dir_for("image.jpg"), PathBuf::from("recovered").join("image"));
        assert_eq!(output_dir_for("dump.bin"), PathBuf::from("recovered").join("dump"));
        assert_eq!(output_dir_for("no_ext"), PathBuf::from("recovered").join("no_ext"));
    }
}

