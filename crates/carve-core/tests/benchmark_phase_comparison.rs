/// Phase 2 entropy scoring vs Phase 2 decode-aware scoring benchmark.
///
/// Runs the full pipeline on the Canon IXUS 310 HS fixtures and compares:
///   Phase 2 (entropy scoring) — best offset chosen by entropy-only ranking
///   Phase 2 (decode scoring)  — best offset chosen by decode-aware ranking
///
/// Run with: cargo test -p carve-core benchmark_phase -- --nocapture

use std::path::PathBuf;
use carve_core::jpeg::validate::{PatchEoiPolicy, ValidationOptions};
use carve_core::reconstruct::camera_profile::CameraJpegProfile;
use carve_core::reconstruct::rebuilder::{OffsetSearchOptions, rebuild_with_offset_search};
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

fn corrupted_fixtures() -> Vec<PathBuf> {
    let dir = fixture_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.contains("missing_soi")
        })
        .collect();
    paths.sort();
    paths
}

#[derive(Clone, Copy)]
enum FixtureKind {
    Clean,
    Corrupted,
}

struct CandidateRow {
    fixture_kind:        &'static str,
    fixture:             String,
    dims:                String,
    status:              String,
    entropy_best_offset: usize,
    entropy_best_score:  f32,
    decode_best_offset:  usize,
    decode_best_score:   f32,
    decode_used:         bool,
    score_gain:          f32,
}

#[test]
fn benchmark_phase_comparison() {
    let mut fixtures: Vec<(FixtureKind, PathBuf)> = clean_fixtures()
        .into_iter()
        .map(|path| (FixtureKind::Clean, path))
        .collect();
    fixtures.extend(corrupted_fixtures().into_iter().map(|path| (FixtureKind::Corrupted, path)));
    assert!(!fixtures.is_empty(), "no fixtures found");

    let options = ValidationOptions {
        allow_truncated: true,
        max_size: usize::MAX,
        patch_eoi: PatchEoiPolicy::Append,
    };

    let profile  = CameraJpegProfile::canon_ixus_310hs();
    let out_dir  = std::env::temp_dir().join("carve_benchmark_phase");
    std::fs::create_dir_all(&out_dir).unwrap();

    let entropy_opts = OffsetSearchOptions { max_offset: 64, step: 1, decode_score: false };
    let decode_opts = OffsetSearchOptions { max_offset: 64, step: 1, decode_score: true };

    let mut rows: Vec<CandidateRow> = Vec::new();
    let mut fixtures_processed = 0usize;
    let mut fixtures_skipped   = 0usize;

    for (kind, path) in &fixtures {
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

        // Offset search writes to a subdirectory per fixture and scoring mode.
        let sub_dir = out_dir.join(&name);
        std::fs::create_dir_all(&sub_dir).unwrap();
        std::fs::create_dir_all(sub_dir.join("entropy")).unwrap();
        std::fs::create_dir_all(sub_dir.join("decode")).unwrap();
        let entropy_results = rebuild_with_offset_search(
            &bytes, &candidates, &profile, &sub_dir.join("entropy"), &entropy_opts,
        ).unwrap();
        let decode_results = rebuild_with_offset_search(
            &bytes, &candidates, &profile, &sub_dir.join("decode"), &decode_opts,
        ).unwrap();

        for (i, candidate) in candidates.iter().enumerate() {
            let (width, height) = match (candidate.width, candidate.height) {
                (Some(w), Some(h)) => (w, h),
                _ => continue,
            };

            let (entropy_best_offset, entropy_best_score) = if let Some(results) = entropy_results.get(i) {
                results.iter()
                    .max_by(|a, b| a.final_score.partial_cmp(&b.final_score).unwrap())
                    .map(|r| (r.offset, r.final_score))
                    .unwrap_or((0, 0.0))
            } else {
                (0, 0.0)
            };

            let (decode_best_offset, decode_best_score, decode_used) = if let Some(results) = decode_results.get(i) {
                results.iter()
                    .max_by(|a, b| a.final_score.partial_cmp(&b.final_score).unwrap())
                    .map(|r| (r.offset, r.final_score, r.used_decode_score))
                    .unwrap_or((0, 0.0, false))
            } else {
                (0, 0.0, false)
            };

            rows.push(CandidateRow {
                fixture_kind: match kind {
                    FixtureKind::Clean => "clean",
                    FixtureKind::Corrupted => "corrupted",
                },
                fixture:             name.clone(),
                dims:                format!("{}×{}", width, height),
                status:              format!("{:?}", candidate.status),
                entropy_best_offset,
                entropy_best_score,
                decode_best_offset,
                decode_best_score,
                decode_used,
                score_gain:          decode_best_score - entropy_best_score,
            });
        }
    }

    let _ = std::fs::remove_dir_all(&out_dir);

    // ── Print results table ──────────────────────────────────────────────────
    println!("\nPhase 2 Entropy vs Decode Benchmark");
    println!("Fixtures processed: {}  skipped: {}\n", fixtures_processed, fixtures_skipped);

    println!(
        "{:<10} {:<22} {:<12} {:<11} {:>8} {:>8} {:>8} {:>8} {:>7}",
        "Kind", "Fixture", "Dimensions", "Status", "Ent off",
        "Ent", "Dec off", "Decode", "Used",
    );
    println!("{}", "-".repeat(110));

    for r in &rows {
        println!(
            "{:<10} {:<22} {:<12} {:<11} {:>8} {:>8.3} {:>8} {:>8.3} {:>7}",
            r.fixture_kind,
            r.fixture,
            r.dims,
            r.status,
            r.entropy_best_offset,
            r.entropy_best_score,
            r.decode_best_offset,
            r.decode_best_score,
            if r.decode_used { "yes" } else { "no" },
        );
    }

    // ── Aggregate statistics ─────────────────────────────────────────────────
    println!("\n--- Aggregate statistics ---");
    let n = rows.len() as f32;
    if n > 0.0 {
        let avg_entropy: f32 = rows.iter().map(|r| r.entropy_best_score).sum::<f32>() / n;
        let avg_decode:  f32 = rows.iter().map(|r| r.decode_best_score).sum::<f32>() / n;
        let improved  = rows.iter().filter(|r| r.score_gain > 0.001).count();
        let decode_used = rows.iter().filter(|r| r.decode_used).count();
        let best_gains: Vec<(f32, usize, usize, &str)> = rows.iter()
            .map(|r| (r.score_gain, r.entropy_best_offset, r.decode_best_offset, r.fixture.as_str()))
            .filter(|(g, _, _, _)| *g > 0.001)
            .collect();
        let clean_rows: Vec<&CandidateRow> = rows.iter().filter(|r| r.fixture_kind == "clean").collect();
        let corrupted_rows: Vec<&CandidateRow> = rows.iter().filter(|r| r.fixture_kind == "corrupted").collect();

        println!("Candidates with dimensions:  {}", rows.len());
        println!("Average entropy score:       {:.3}", avg_entropy);
        println!("Average decode score:        {:.3}", avg_decode);
        println!("Decode score used:           {} / {}", decode_used, rows.len());
        println!("Candidates improved by decode scoring: {} / {}", improved, rows.len());
        if !clean_rows.is_empty() {
            let clean_avg = clean_rows.iter().map(|r| r.decode_best_score - r.entropy_best_score).sum::<f32>() / clean_rows.len() as f32;
            println!("Average clean score gain:    {:+.3}", clean_avg);
        }
        if !corrupted_rows.is_empty() {
            let corrupted_avg = corrupted_rows.iter().map(|r| r.decode_best_score - r.entropy_best_score).sum::<f32>() / corrupted_rows.len() as f32;
            println!("Average corrupted score gain: {:+.3}", corrupted_avg);
        }
        if !best_gains.is_empty() {
            println!("Gains breakdown:");
            let mut sorted_gains = best_gains.clone();
            sorted_gains.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
            for (gain, entropy_offset, decode_offset, name) in sorted_gains.iter().take(5) {
                println!(
                    "  +{:.3} {} — entropy offset {} -> decode offset {}",
                    gain, name, entropy_offset, decode_offset
                );
            }
        }
    }

    println!("\n--- Key findings ---");
    println!("Entropy scoring ranks offsets from compressed-byte statistics only.");
    println!("Decode-aware scoring can prefer a different offset when the rebuilt image decodes successfully.");
    println!("Corrupted fixtures expose the fallback path: decode scoring remains stable because it drops back to entropy when decode fails.");

    // Assertions: benchmark completes and produces at least one result row.
    assert!(!rows.is_empty(), "benchmark produced no scoreable rows");
    assert!(rows.iter().all(|r| (0.0..=1.0).contains(&r.entropy_best_score)));
    assert!(rows.iter().all(|r| (0.0..=1.0).contains(&r.decode_best_score)));
}
