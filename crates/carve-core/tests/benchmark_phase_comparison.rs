/// Phase 1 vs Phase 2 benchmark.
///
/// Runs the full pipeline on every clean Canon IXUS 310 HS fixture and compares:
///   Phase 1 — raw carved output (original header preserved from disk)
///   Phase 2 — camera-profile rebuild (Canon IXUS 310 HS header synthesized)
///   Phase 2 + offset search — best-scoring entropy alignment (max_offset=64)
///
/// Run with: cargo test -p carve-core benchmark_phase -- --nocapture

use std::path::PathBuf;
use carve_core::jpeg::parse::parse_until_sos;
use carve_core::jpeg::validate::{PatchEoiPolicy, ValidationOptions};
use carve_core::reconstruct::camera_profile::CameraJpegProfile;
use carve_core::reconstruct::rebuilder::{OffsetSearchOptions, rebuild_with_offset_search};
use carve_core::reconstruct::scorer::score_entropy_stream;
use carve_core::scanner::{apply_validated_overlap_policy, recover_candidates, OverlapOptions};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn clean_fixtures() -> Vec<PathBuf> {
    let dir = fixture_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ext  = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            (ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg"))
                && !name.contains("missing_soi")
        })
        .collect();
    paths.sort();
    paths
}

struct CandidateRow {
    fixture:         String,
    dims:            String,
    status:          String,
    entropy_bytes:   usize,
    p1_score:        f32,
    p2_score:        f32,
    best_offset:     usize,
    best_offset_score: f32,
    score_gain:      f32,
}

#[test]
fn benchmark_phase_comparison() {
    let fixtures = clean_fixtures();
    assert!(!fixtures.is_empty(), "no fixtures found");

    let options = ValidationOptions {
        allow_truncated: true,
        max_size: usize::MAX,
        patch_eoi: PatchEoiPolicy::Append,
    };

    let profile  = CameraJpegProfile::canon_ixus_310hs();
    let out_dir  = std::env::temp_dir().join("carve_benchmark_phase");
    std::fs::create_dir_all(&out_dir).unwrap();

    let offset_opts = OffsetSearchOptions { max_offset: 64, step: 1, decode_score: false };

    let mut rows: Vec<CandidateRow> = Vec::new();
    let mut fixtures_processed = 0usize;
    let mut fixtures_skipped   = 0usize;

    for path in &fixtures {
        let name  = path.file_name().unwrap().to_string_lossy().to_string();
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => { fixtures_skipped += 1; continue; }
        };

        let candidates_raw = recover_candidates(&bytes, ValidationOptions { max_size: bytes.len(), ..options });
        let candidates = apply_validated_overlap_policy(
            candidates_raw,
            OverlapOptions { keep_overlaps: false },
        );

        if candidates.is_empty() {
            fixtures_skipped += 1;
            continue;
        }
        fixtures_processed += 1;

        // Offset search writes to a subdirectory per fixture.
        let sub_dir = out_dir.join(&name);
        std::fs::create_dir_all(&sub_dir).unwrap();
        let offset_results = rebuild_with_offset_search(
            &bytes, &candidates, &profile, &sub_dir, &offset_opts,
        ).unwrap();

        for (i, candidate) in candidates.iter().enumerate() {
            let (width, height) = match (candidate.width, candidate.height) {
                (Some(w), Some(h)) => (w, h),
                _ => continue,
            };

            // Phase 1: score the entropy stream from the raw carved bytes.
            let (scan_start, entropy_end) = match parse_until_sos(&bytes, candidate.start, bytes.len()).ok() {
                Some(pre_sos) => {
                    let ee = if candidate.patched_eoi { candidate.end } else { candidate.end.saturating_sub(2) };
                    (pre_sos.scan_start, ee)
                }
                None => continue,
            };
            if scan_start >= entropy_end { continue; }
            let entropy_len = entropy_end - scan_start;
            let p1_score = score_entropy_stream(&bytes[scan_start..entropy_end]);

            // Phase 2 (offset 0): same entropy stream, canonical header.
            // Score is identical to Phase 1 at offset 0 (same bytes scored).
            let p2_score_val = p1_score.total; // by construction: same entropy, different header

            // Phase 2 + offset search: best score across offsets 0..=64.
            let (best_offset, best_score) = if let Some(results) = offset_results.get(i) {
                results.iter()
                    .max_by(|a, b| a.final_score.partial_cmp(&b.final_score).unwrap())
                    .map(|r| (r.offset, r.final_score))
                    .unwrap_or((0, p2_score_val))
            } else {
                (0, p2_score_val)
            };

            rows.push(CandidateRow {
                fixture:           name.clone(),
                dims:              format!("{}×{}", width, height),
                status:            format!("{:?}", candidate.status),
                entropy_bytes:     entropy_len,
                p1_score:          p1_score.total,
                p2_score:          p2_score_val,
                best_offset,
                best_offset_score: best_score,
                score_gain:        best_score - p1_score.total,
            });
        }
    }

    let _ = std::fs::remove_dir_all(&out_dir);

    // ── Print results table ──────────────────────────────────────────────────
    println!("\nPhase 1 vs Phase 2 Benchmark");
    println!("Fixtures processed: {}  skipped: {}\n", fixtures_processed, fixtures_skipped);

    println!(
        "{:<22} {:<12} {:<11} {:>10} {:>8} {:>8} {:>10} {:>10}",
        "Fixture", "Dimensions", "Status", "Entropy B", "P1 score",
        "P2 score", "Best off", "Best score",
    );
    println!("{}", "-".repeat(100));

    for r in &rows {
        println!(
            "{:<22} {:<12} {:<11} {:>10} {:>8.3} {:>8.3} {:>10} {:>10.3}",
            r.fixture, r.dims, r.status, r.entropy_bytes,
            r.p1_score, r.p2_score, r.best_offset, r.best_offset_score,
        );
    }

    // ── Aggregate statistics ─────────────────────────────────────────────────
    println!("\n--- Aggregate statistics ---");
    let n = rows.len() as f32;
    if n > 0.0 {
        let avg_p1:   f32 = rows.iter().map(|r| r.p1_score).sum::<f32>() / n;
        let avg_best: f32 = rows.iter().map(|r| r.best_offset_score).sum::<f32>() / n;
        let improved  = rows.iter().filter(|r| r.score_gain > 0.001).count();
        let best_gains: Vec<(f32, usize, &str)> = rows.iter()
            .map(|r| (r.score_gain, r.best_offset, r.fixture.as_str()))
            .filter(|(g, _, _)| *g > 0.001)
            .collect();

        println!("Candidates with dimensions:  {}", rows.len());
        println!("Average Phase 1 score:       {:.3}", avg_p1);
        println!("Average best-offset score:   {:.3}", avg_best);
        println!("Candidates improved by offset search: {} / {}", improved, rows.len());
        if !best_gains.is_empty() {
            println!("Gains breakdown:");
            let mut sorted_gains = best_gains.clone();
            sorted_gains.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
            for (gain, offset, name) in sorted_gains.iter().take(5) {
                println!("  +{:.3} at offset {} — {}", gain, offset, name);
            }
        }
    }

    println!("\n--- Key findings ---");
    println!("Phase 2 canonical header uses the same entropy stream as Phase 1;");
    println!("byte-entropy scores at offset 0 are therefore identical.");
    println!("The offset search explores alignment within the entropy stream,");
    println!("which can raise the diversity/entropy score when offset 0 is misaligned.");

    // Assertions: benchmark completes and produces at least one result row.
    assert!(!rows.is_empty(), "benchmark produced no scoreable rows");
    assert!(rows.iter().all(|r| (0.0..=1.0).contains(&r.p1_score)));
    assert!(rows.iter().all(|r| (0.0..=1.0).contains(&r.best_offset_score)));
}
