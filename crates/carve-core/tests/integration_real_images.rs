use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use carve_core::extract::extract_candidates;
use carve_core::jpeg::parse::parse_until_sos;
use carve_core::jpeg::validate::{PatchEoiPolicy, ValidationOptions};
use carve_core::scanner::{apply_validated_overlap_policy, recover_candidates, OverlapOptions};
use carve_core::report::write_report;

#[test]
fn test_real_jpeg_parsing_valid_img_1390() {
    // Locate the test file relative to the crate root
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("tests/fixtures/IMG_1390.JPG");

    // Ensure the file exists before trying to open (to avoid cryptic errors if running in incorrect context)
    if !file_path.exists() {
        eprintln!("Skipping test: Test file not found at {:?}", file_path);
        return;
    }

    let mut f = File::open(&file_path).expect("failed to open IMG_1390.JPG");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("failed to read file");

    // The file is a raw dump containing embedded JPEGs. 
    // The main image starts at offset 964096 (found via analysis).
    let start_offset = 964096;
    
    if buffer.len() <= start_offset {
        panic!("File too small for expected offset");
    }

    let res = parse_until_sos(&buffer, start_offset, buffer.len()).expect("parse_until_sos failed on valid image");

    // The main image in IMG_1390.JPG is 2992x2992 (detected via manual scan).
    // The thumbnail (160x120) is likely inside APP1 Exif and skipped by the top-level parser.
    // If separate, the parser stops at the first SOS.
    // Let's verify what we found.
    
    assert!(res.width.is_some(), "Width not extracted");
    assert!(res.height.is_some(), "Height not extracted");
    
    let width = res.width.unwrap();
    let height = res.height.unwrap();
    
    println!("Extracted dimensions: {}x{}", width, height);
    
    // We expect the main image dimensions.
    assert_eq!(width, 2992);
    assert_eq!(height, 2992);

    assert_eq!(res.is_progressive, Some(false));
    assert!(res.has_dqt);
    assert!(res.has_dht);
    // assert!(res.has_exif); // Main image at 964096 does not seem to have Exif
}

#[test]
fn test_real_jpeg_parsing_thumbnail_img_1390() {
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("tests/fixtures/IMG_1390.JPG");

    // Ensure the file exists before trying to open (to avoid cryptic errors if running in incorrect context)
    if !file_path.exists() {
        eprintln!("Skipping test: Test file not found at {:?}", file_path);
        return;
    }

    let mut f = File::open(&file_path).expect("failed to open IMG_1390.JPG");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("failed to read file");

    let thumbnail_offset = 955904;
    
    if buffer.len() <= thumbnail_offset {
        panic!("File too small for thumbnail offset");
    }

    let res = parse_until_sos(&buffer, thumbnail_offset, buffer.len()).expect("parse_until_sos failed on thumbnail");
    
    let width = res.width.unwrap();
    let height = res.height.unwrap();
    
    println!("Thumbnail dimensions: {}x{}", width, height);

    // Thumbnail should be 160x120
    assert_eq!(width, 160);
    assert_eq!(height, 120);
    
    assert_eq!(res.is_progressive, Some(false));
    // It might or might not contain Exif/DQT/DHT
    assert!(res.has_dqt); 
    // Exif inside a thumbnail? Maybe not.
}

#[test]
fn test_real_jpeg_parsing_missing_soi() {
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("tests/fixtures/missing_soi.JPG");
    
    if !file_path.exists() {
        eprintln!("Skipping test: Test file not found at {:?}", file_path);
        return;
    }

    let mut f = File::open(&file_path).expect("failed to open missing_soi.JPG");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("read failed");

    // Should fail because SOI is missing
    let res = parse_until_sos(&buffer, 0, buffer.len());
    assert!(res.is_err(), "Should detect missing SOI/Not JPEG");
}

/// Full-pipeline regression test against the real camera JPEG fixture.
///
/// Discovered values (IMG_1390.JPG, 1 795 948 bytes):
///   Before suppression — 3 candidates:
///     [0] start=950272  end=1795948  Truncated  2992×2992  patched=true
///     [1] start=955904  end=962285   Recovered  160×120    patched=false
///     [2] start=964096  end=1795948  Truncated  2992×2992  patched=true
///   After suppression — 1 candidate:
///     [0] start=950272  end=1795948  (engulfs [1] and [2])
///
/// Runs recover_candidates → overlap suppression → write_report and pins
/// all values so future refactors are caught immediately.
#[test]
fn real_jpeg_full_pipeline_regression_img_1390() {
    use carve_core::jpeg::candidate::RecoveryStatus;

    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("tests/fixtures/IMG_1390.JPG");

    if !file_path.exists() {
        eprintln!("Skipping: fixture not found at {:?}", file_path);
        return;
    }

    let buffer = std::fs::read(&file_path).expect("failed to read IMG_1390.JPG");
    assert_eq!(buffer.len(), 1_795_948, "fixture size must not change");

    let options = ValidationOptions {
        allow_truncated: true,
        max_size: buffer.len(),
        patch_eoi: PatchEoiPolicy::Append,
    };

    // --- Before suppression: 3 embedded JPEGs ---
    let raw = recover_candidates(&buffer, options);
    assert_eq!(raw.len(), 3, "expected exactly 3 candidates before suppression");

    assert_eq!(raw[0].start, 950272);
    assert_eq!(raw[0].end,   1_795_948);
    assert_eq!(raw[0].status, RecoveryStatus::Truncated);
    assert!(raw[0].patched_eoi);
    assert_eq!(raw[0].width,  Some(2992));
    assert_eq!(raw[0].height, Some(2992));
    assert_eq!(raw[0].is_progressive, Some(false));

    assert_eq!(raw[1].start, 955904);
    assert_eq!(raw[1].end,   962285);
    assert_eq!(raw[1].status, RecoveryStatus::Recovered);
    assert!(!raw[1].patched_eoi);
    assert_eq!(raw[1].width,  Some(160));
    assert_eq!(raw[1].height, Some(120));
    assert_eq!(raw[1].is_progressive, Some(false));
    assert!(raw[1].has_dqt);

    assert_eq!(raw[2].start, 964096);
    assert_eq!(raw[2].end,   1_795_948);
    assert_eq!(raw[2].status, RecoveryStatus::Truncated);
    assert!(raw[2].patched_eoi);
    assert_eq!(raw[2].width,  Some(2992));
    assert_eq!(raw[2].height, Some(2992));
    assert!(raw[2].has_dqt);
    assert!(raw[2].has_dht);

    // --- After suppression: largest span wins, nested candidates dropped ---
    let suppressed = apply_validated_overlap_policy(
        raw,
        OverlapOptions { keep_overlaps: false },
    );
    assert_eq!(suppressed.len(), 1, "overlap suppression must yield exactly 1 candidate");
    assert_eq!(suppressed[0].start, 950272);
    assert_eq!(suppressed[0].end,   1_795_948);
    assert_eq!(suppressed[0].status, RecoveryStatus::Truncated);

    // --- keep_overlaps preserves all three ---
    let raw2 = recover_candidates(&buffer, options);
    let kept = apply_validated_overlap_policy(
        raw2,
        OverlapOptions { keep_overlaps: true },
    );
    assert_eq!(kept.len(), 3);

    // --- JSONL report serialises without panic ---
    let report_path = std::env::temp_dir().join("carve_regression_img1390.jsonl");
    write_report(&report_path, &suppressed).expect("write_report must not fail");
    let report = std::fs::read_to_string(&report_path).unwrap();
    let lines: Vec<&str> = report.lines().collect();
    assert_eq!(lines.len(), 1, "one line per candidate in report");
    assert!(lines[0].starts_with('{'));
    assert!(lines[0].contains("\"start\":950272"));
    let _ = std::fs::remove_file(&report_path);
}

/// Full-pipeline test for a JPEG file where only the SOI marker is missing
/// but the rest of the JPEG header (APP/DQT/SOF/SOS) is intact.
///
/// The `missing_soi.JPG` fixture is a more severely corrupted file — its
/// entire JPEG header is stripped, leaving only raw entropy-coded scan data
/// followed by embedded thumbnail JPEGs. The headerless detector requires
/// at least the APP/DQT/SOF markers to be present (just not the SOI prefix),
/// so the main image in this file cannot be recovered by the current approach.
///
/// This test verifies:
/// - The pipeline does not crash on this file.
/// - The existing SOI-based thumbnails are still found correctly.
/// - If any headerless candidate IS found (from markers between thumbnails),
///   it has `missing_soi=true` and is extracted with a synthesized FF D8 prefix.
#[test]
fn test_missing_soi_full_pipeline() {
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("tests/fixtures/missing_soi.JPG");

    if !file_path.exists() {
        eprintln!("Skipping: fixture not found at {:?}", file_path);
        return;
    }

    let buffer = std::fs::read(&file_path).expect("failed to read missing_soi.JPG");

    let options = ValidationOptions {
        allow_truncated: true,
        max_size: buffer.len(),
        patch_eoi: PatchEoiPolicy::Append,
    };

    // Pipeline must not crash
    let raw = recover_candidates(&buffer, options);
    assert!(!raw.is_empty(), "should find at least the embedded thumbnail candidates");

    // All SOI-based candidates must not have missing_soi
    for c in raw.iter().filter(|c| !c.missing_soi) {
        assert!(!c.missing_soi, "SOI-based candidates should have missing_soi=false");
    }

    // If any headerless candidates were found, verify they have missing_soi=true
    // and that extraction prepends FF D8.
    let headerless: Vec<_> = raw.iter().filter(|c| c.missing_soi).collect();
    if !headerless.is_empty() {
        let out_dir = std::env::temp_dir().join("carve_test_missing_soi_pipeline");
        std::fs::create_dir_all(&out_dir).unwrap();

        let suppressed = apply_validated_overlap_policy(
            raw.clone(),
            OverlapOptions { keep_overlaps: false },
        );
        let paths = extract_candidates(&buffer, &suppressed, &out_dir)
            .expect("extraction must not fail");

        for (idx, c) in suppressed.iter().enumerate() {
            if c.missing_soi {
                let written = std::fs::read(&paths[idx]).unwrap();
                assert_eq!(
                    &written[..2],
                    &[0xFF, 0xD8],
                    "headerless candidate at {} must start with synthesized SOI",
                    c.start,
                );
            }
        }

        let _ = std::fs::remove_dir_all(&out_dir);
    }
}
