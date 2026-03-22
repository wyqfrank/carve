use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use carve_core::extract::extract_candidates;
use carve_core::jpeg::marker_dump::dump_jpeg_segments;
use carve_core::jpeg::parse::parse_until_sos;
use carve_core::jpeg::restart_scan::scan_restart_markers;
use carve_core::jpeg::validate::{PatchEoiPolicy, ValidationOptions};
use carve_core::reconstruct::camera_profile::CameraJpegProfile;
use carve_core::reconstruct::rebuilder::{rebuild_candidates, rebuild_with_offset_search, OffsetSearchOptions};
use carve_core::report::{write_report_with_scoring, CandidateScoringInfo};
use carve_core::scanner::{apply_validated_overlap_policy, recover_candidates, OverlapOptions};

const USAGE: &str = "\
Usage:
  carve [--keep-overlaps] [--rebuild] [--offset-search] [--decode-score] [--offset-max N] <file|pattern> ...
  carve --dump [--json] <file>

Flags:
  --keep-overlaps      Emit all candidates without overlap suppression
  --rebuild            Also write camera-profile rebuilt JPEGs (rebuilt_NNN.jpg)
  --offset-search      For each candidate try multiple entropy offsets (rebuilt_NNN_offset_MMMM.jpg)
  --decode-score       Use decode-aware scoring for offset ranking with entropy fallback
  --offset-max N       Maximum byte offset to try with --offset-search (default: 512)
  --dump               Print JPEG segment structure instead of carving
  --json               With --dump: output JSON instead of a text table";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliOptions {
    file_paths: Vec<String>,
    keep_overlaps: bool,
    rebuild: bool,
    offset_search: bool,
    decode_score: bool,
    offset_max: usize,
    dump: bool,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<CliOptions, String> {
    if args.len() < 2 {
        return Err(USAGE.to_string());
    }

    let mut keep_overlaps = false;
    let mut rebuild = false;
    let mut offset_search = false;
    let mut decode_score = false;
    let mut offset_max: usize = OffsetSearchOptions::default().max_offset;
    let mut dump = false;
    let mut json = false;
    let mut file_paths: Vec<String> = Vec::new();
    let mut args_iter = args[1..].iter().peekable();

    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "--keep-overlaps" => keep_overlaps = true,
            "--rebuild" => rebuild = true,
            "--offset-search" => offset_search = true,
            "--decode-score" => decode_score = true,
            "--offset-max" => {
                let val = args_iter.next().ok_or_else(|| {
                    format!("--offset-max requires a value\n{USAGE}")
                })?;
                offset_max = val.parse::<usize>().map_err(|_| {
                    format!("--offset-max value must be a non-negative integer, got '{val}'\n{USAGE}")
                })?;
                offset_search = true; // --offset-max implies --offset-search
            }
            "--dump" => dump = true,
            "--json" => json = true,
            arg if arg.starts_with('-') => {
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
        rebuild,
        offset_search,
        decode_score,
        offset_max,
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

                // Print restart marker summary for the candidate's entropy slice.
                let rst_summary = if let Ok(pre_sos) = parse_until_sos(&bytes, c.start, c.end - c.start) {
                    scan_restart_markers(&bytes, pre_sos.scan_start, c.end)
                } else {
                    scan_restart_markers(&bytes, c.start, c.end)
                };

                if rst_summary.count == 0 {
                    println!("    RST markers: none");
                } else {
                    let regularity = if rst_summary.is_regular { "yes" } else { "no" };
                    if let Some(mean) = rst_summary.mean_interval {
                        println!(
                            "    RST markers: {} (mean interval: {:.0} bytes, regular: {})",
                            rst_summary.count, mean, regularity
                        );
                    } else {
                        println!("    RST markers: {}", rst_summary.count);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Extraction failed: {}", e);
            process::exit(1);
        }
    }

    if cli.rebuild {
        let profile = CameraJpegProfile::canon_ixus_310hs();
        match rebuild_candidates(&bytes, &candidates, &profile, &out_dir) {
            Ok(rebuilt_paths) => {
                let mut rebuilt_count = 0;
                for (i, maybe_path) in rebuilt_paths.iter().enumerate() {
                    if let Some(path) = maybe_path {
                        println!("  [{}] rebuilt → {}", i, path.display());
                        rebuilt_count += 1;
                    } else {
                        println!("  [{}] rebuild skipped (dimensions unknown)", i);
                    }
                }
                println!("Rebuilt {} of {} candidate(s)", rebuilt_count, candidates.len());
            }
            Err(e) => {
                eprintln!("Rebuild failed: {}", e);
                process::exit(1);
            }
        }
    }

    let mut report_scoring = vec![None; candidates.len()];

    if cli.offset_search {
        let profile = CameraJpegProfile::canon_ixus_310hs();
        let opts = OffsetSearchOptions {
            max_offset: cli.offset_max,
            step: 1,
            decode_score: cli.decode_score,
        };
        match rebuild_with_offset_search(&bytes, &candidates, &profile, &out_dir, &opts) {
            Ok(per_candidate) => {
                let total: usize = per_candidate.iter().map(|v| v.len()).sum();
                for (i, results) in per_candidate.iter().enumerate() {
                    if results.is_empty() {
                        println!("  [{}] offset search skipped (dimensions unknown)", i);
                        continue;
                    }
                    // Find the best-scoring result for the summary line.
                    let best = results.iter().max_by(|a, b| {
                        a.final_score.partial_cmp(&b.final_score).unwrap()
                    }).unwrap();
                    println!(
                        "  [{}] {} offset variant(s) — best offset={} score={:.3} [{}] ({})",
                        i,
                        results.len(),
                        best.offset,
                        best.final_score,
                        if best.used_decode_score { "decode" } else { "entropy" },
                        best.path.file_name().unwrap_or_default().to_string_lossy(),
                    );
                    report_scoring[i] = Some(CandidateScoringInfo::from_offset_search_result(best));
                    // Print top-5 by score (descending).
                    let mut ranked: Vec<_> = results.iter().collect();
                    ranked.sort_by(|a, b| b.final_score.partial_cmp(&a.final_score).unwrap());
                    for r in ranked.iter().take(5) {
                        if let Some(decode_score) = &r.decode_score {
                            println!(
                                "    offset={:4}  score={:.3}  decode={:.3}  entropy={:.3}  colour={:.3}  pixel={:.3}  block={:.3}  {}",
                                r.offset,
                                r.final_score,
                                decode_score.total,
                                r.score.total,
                                decode_score.colour_balance,
                                decode_score.pixel_entropy,
                                decode_score.block_artifact_score,
                                r.path.file_name().unwrap_or_default().to_string_lossy(),
                            );
                        } else {
                            println!(
                                "    offset={:4}  score={:.3}  entropy={:.3}  unique={:.3}  unexpected={}  {}",
                                r.offset,
                                r.final_score,
                                r.score.total,
                                r.score.unique_byte_ratio,
                                r.score.unexpected_markers,
                                r.path.file_name().unwrap_or_default().to_string_lossy(),
                            );
                        }
                    }
                }
                println!("Offset search: {} file(s) written", total);
            }
            Err(e) => {
                eprintln!("Offset search failed: {}", e);
                process::exit(1);
            }
        }
    }

    let report_path = out_dir.join("report.jsonl");
    if let Err(e) = write_report_with_scoring(&report_path, &candidates, &report_scoring) {
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
        assert!(!parsed.decode_score);
    }

    #[test]
    fn parses_multiple_files() {
        let parsed = parse_args(&args(&["carve", "a.jpg", "b.jpg", "c.jpg"])).unwrap();
        assert_eq!(parsed.file_paths, vec!["a.jpg", "b.jpg", "c.jpg"]);
        assert!(!parsed.keep_overlaps);
        assert!(!parsed.decode_score);
    }

    #[test]
    fn parses_keep_overlaps_with_multiple_files() {
        let parsed = parse_args(&args(&["carve", "--keep-overlaps", "a.jpg", "b.jpg"])).unwrap();
        assert_eq!(parsed.file_paths, vec!["a.jpg", "b.jpg"]);
        assert!(parsed.keep_overlaps);
    }

    #[test]
    fn parses_decode_score_flag() {
        let parsed = parse_args(&args(&["carve", "--offset-search", "--decode-score", "image.jpg"])).unwrap();
        assert!(parsed.offset_search);
        assert!(parsed.decode_score);
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
    fn parses_rebuild_flag() {
        let parsed = parse_args(&args(&["carve", "--rebuild", "image.jpg"])).unwrap();
        assert!(parsed.rebuild);
        assert!(!parsed.keep_overlaps);
        assert_eq!(parsed.file_paths, vec!["image.jpg"]);
    }

    #[test]
    fn rebuild_false_by_default() {
        let parsed = parse_args(&args(&["carve", "image.jpg"])).unwrap();
        assert!(!parsed.rebuild);
    }

    #[test]
    fn parses_offset_search_flag() {
        let parsed = parse_args(&args(&["carve", "--offset-search", "image.jpg"])).unwrap();
        assert!(parsed.offset_search);
        assert_eq!(parsed.offset_max, 512);
    }

    #[test]
    fn parses_offset_max_flag() {
        let parsed = parse_args(&args(&["carve", "--offset-max", "256", "image.jpg"])).unwrap();
        assert!(parsed.offset_search);
        assert_eq!(parsed.offset_max, 256);
    }

    #[test]
    fn offset_max_implies_offset_search() {
        let parsed = parse_args(&args(&["carve", "--offset-max", "100", "image.jpg"])).unwrap();
        assert!(parsed.offset_search);
    }

    #[test]
    fn offset_search_false_by_default() {
        let parsed = parse_args(&args(&["carve", "image.jpg"])).unwrap();
        assert!(!parsed.offset_search);
        assert_eq!(parsed.offset_max, 512);
    }

    #[test]
    fn rejects_offset_max_without_value() {
        let err = parse_args(&args(&["carve", "--offset-max", "image.jpg"])).unwrap_err();
        // "image.jpg" is not a valid usize, so should get a parse error
        assert!(err.contains("integer") || err.contains("offset-max"));
    }

    #[test]
    fn rejects_offset_max_non_integer() {
        let err = parse_args(&args(&["carve", "--offset-max", "abc", "image.jpg"])).unwrap_err();
        assert!(err.contains("integer"));
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
