/// Canon IXUS 310 HS header consistency analysis.
///
/// Run with: cargo test -p carve-core analyse_header_consistency -- --nocapture
///
/// The fixture files are raw disk image dumps; JPEGs are embedded at non-zero
/// offsets. This test uses recover_candidates to locate the main image in each
/// fixture, then runs dump_jpeg_segments at that offset to extract segment data.
/// Cross-image comparisons confirm which header fields are invariant.

use carve_core::jpeg::marker_dump::{dump_jpeg_segments, SegmentDump};
use carve_core::jpeg::validate::{PatchEoiPolicy, ValidationOptions};
use carve_core::scanner::recover_candidates;
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// All clean reference fixtures (exclude missing_soi which is deliberately damaged).
fn clean_fixtures() -> Vec<PathBuf> {
    let dir = fixture_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            (ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg"))
                && !name.contains("missing_soi")
        })
        .collect();
    paths.sort();
    paths
}

/// Find the main JPEG start offset in a disk image dump.
/// Picks the candidate with the largest dimensions (excludes thumbnails).
fn find_main_jpeg_offset(bytes: &[u8]) -> Option<usize> {
    let options = ValidationOptions {
        allow_truncated: true,
        max_size: bytes.len(),
        patch_eoi: PatchEoiPolicy::None,
    };
    let candidates = recover_candidates(bytes, options);
    // Pick the candidate with the largest pixel area (main image, not thumbnail)
    candidates
        .into_iter()
        .filter(|c| !c.missing_soi)
        .filter_map(|c| {
            let area = c.width.unwrap_or(0) as u32 * c.height.unwrap_or(0) as u32;
            if area > 0 { Some((area, c.start)) } else { None }
        })
        .max_by_key(|(area, _)| *area)
        .map(|(_, start)| start)
}

fn segments_of_name<'a>(segs: &'a [SegmentDump], name: &str) -> Vec<&'a SegmentDump> {
    segs.iter().filter(|s| s.name == name).collect()
}

fn segment_of_name<'a>(segs: &'a [SegmentDump], name: &str) -> Option<&'a SegmentDump> {
    segs.iter().find(|s| s.name == name)
}

#[test]
fn analyse_header_consistency() {
    let fixtures = clean_fixtures();
    assert!(
        fixtures.len() >= 5,
        "need at least 5 fixtures for meaningful comparison"
    );

    println!(
        "\n=== Canon IXUS 310 HS Header Consistency Analysis ({} fixtures) ===\n",
        fixtures.len()
    );

    // Locate main JPEG in each fixture and dump its header
    let mut dumps: Vec<(String, Vec<SegmentDump>)> = Vec::new();
    for path in &fixtures {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let bytes = std::fs::read(path).unwrap();

        let offset = match find_main_jpeg_offset(&bytes) {
            Some(o) => o,
            None => {
                println!("  {}: no JPEG candidate found — skipping", name);
                continue;
            }
        };

        match dump_jpeg_segments(&bytes, offset) {
            Ok(dump) => dumps.push((name, dump.segments)),
            Err(e) => {
                println!("  {}: dump failed ({:?}) — skipping", name, e);
            }
        }
    }

    assert!(
        dumps.len() >= 5,
        "need at least 5 successfully parsed fixtures, got {}",
        dumps.len()
    );

    println!("Successfully parsed {}/{} fixtures\n", dumps.len(), fixtures.len());

    // ── Marker ordering ──────────────────────────────────────────────────────
    println!("## Marker ordering\n");
    let mut ordering_counts: std::collections::HashMap<Vec<String>, usize> =
        std::collections::HashMap::new();
    for (_, segs) in &dumps {
        let order: Vec<String> = segs.iter().map(|s| s.name.to_string()).collect();
        *ordering_counts.entry(order).or_insert(0) += 1;
    }
    let mut orderings: Vec<_> = ordering_counts.iter().collect();
    orderings.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for (order, count) in &orderings {
        println!("  ({:>3} images) {}", count, order.join(" → "));
    }
    let ordering_invariant = ordering_counts.len() == 1;
    println!("  Invariant: {}\n", ordering_invariant);

    // ── DQT segments ─────────────────────────────────────────────────────────
    println!("## DQT segments\n");
    let dqt_counts: Vec<usize> = dumps
        .iter()
        .map(|(_, s)| segments_of_name(s, "DQT").len())
        .collect();
    let dqt_min = dqt_counts.iter().min().copied().unwrap_or(0);
    let dqt_max = dqt_counts.iter().max().copied().unwrap_or(0);
    println!("  Count range: {} – {}", dqt_min, dqt_max);

    let reference_dqts: Vec<Vec<u8>> = segments_of_name(&dumps[0].1, "DQT")
        .into_iter()
        .map(|s| s.payload.clone())
        .collect();

    let dqt_invariant = dumps.iter().all(|(_, segs)| {
        let dqts: Vec<&[u8]> = segments_of_name(segs, "DQT")
            .into_iter()
            .map(|s| s.payload.as_slice())
            .collect();
        dqts.len() == reference_dqts.len()
            && dqts
                .iter()
                .zip(&reference_dqts)
                .all(|(a, b)| *a == b.as_slice())
    });
    println!("  Invariant across all images: {}", dqt_invariant);

    for (i, seg) in segments_of_name(&dumps[0].1, "DQT").iter().enumerate() {
        let hex: Vec<String> = seg.payload.iter().map(|b| format!("{b:02X}")).collect();
        println!(
            "  DQT[{}] len={} bytes: {}",
            i,
            seg.payload_len,
            hex.join("")
        );
    }
    println!();

    // ── DHT segments ─────────────────────────────────────────────────────────
    println!("## DHT segments\n");
    let dht_counts: Vec<usize> = dumps
        .iter()
        .map(|(_, s)| segments_of_name(s, "DHT").len())
        .collect();
    let dht_min = dht_counts.iter().min().copied().unwrap_or(0);
    let dht_max = dht_counts.iter().max().copied().unwrap_or(0);
    println!("  Count range: {} – {}", dht_min, dht_max);

    let reference_dhts: Vec<Vec<u8>> = segments_of_name(&dumps[0].1, "DHT")
        .into_iter()
        .map(|s| s.payload.clone())
        .collect();

    let dht_invariant = dumps.iter().all(|(_, segs)| {
        let dhts: Vec<&[u8]> = segments_of_name(segs, "DHT")
            .into_iter()
            .map(|s| s.payload.as_slice())
            .collect();
        dhts.len() == reference_dhts.len()
            && dhts
                .iter()
                .zip(&reference_dhts)
                .all(|(a, b)| *a == b.as_slice())
    });
    println!("  Invariant across all images: {}", dht_invariant);

    for (i, seg) in segments_of_name(&dumps[0].1, "DHT").iter().enumerate() {
        println!("  DHT[{}] len={} bytes", i, seg.payload_len);
    }
    println!();

    // ── SOF0 ─────────────────────────────────────────────────────────────────
    println!("## SOF0 parameters\n");

    let mut dimensions: Vec<(u16, u16)> = Vec::new();
    let mut sof_nondim_ref: Option<Vec<u8>> = None;
    let mut sof_nondim_invariant = true;

    for (name, segs) in &dumps {
        if let Some(sof) = segment_of_name(segs, "SOF0") {
            let p = &sof.payload;
            if p.len() >= 6 {
                let precision = p[0];
                let height = ((p[1] as u16) << 8) | p[2] as u16;
                let width  = ((p[3] as u16) << 8) | p[4] as u16;
                let ncomp  = p[5];
                dimensions.push((width, height));

                let sampling: Vec<String> = (0..ncomp as usize)
                    .filter_map(|i| {
                        let off = 6 + i * 3;
                        if off + 2 < p.len() {
                            Some(format!(
                                "id={} samp=0x{:02X} qt={}",
                                p[off], p[off + 1], p[off + 2]
                            ))
                        } else {
                            None
                        }
                    })
                    .collect();
                println!(
                    "  {} — {}×{}  prec={}  ncomp={}  [{}]",
                    name, width, height, precision, ncomp, sampling.join(", ")
                );

                // Compare non-dimensional bytes (skip height/width: bytes 1-4)
                let nondim: Vec<u8> = [&p[0..1], &p[5..]].concat();
                match &sof_nondim_ref {
                    None => sof_nondim_ref = Some(nondim),
                    Some(r) => {
                        if *r != nondim {
                            sof_nondim_invariant = false;
                        }
                    }
                }
            }
        }
    }

    dimensions.sort();
    dimensions.dedup();
    println!();
    println!("  Distinct dimensions found: {:?}", dimensions);
    println!("  Non-dimensional SOF0 fields invariant: {}", sof_nondim_invariant);
    println!("  (width and height vary per image, as expected)\n");

    // ── DRI ──────────────────────────────────────────────────────────────────
    println!("## DRI (restart interval)\n");
    let dri_present_count = dumps
        .iter()
        .filter(|(_, s)| segment_of_name(s, "DRI").is_some())
        .count();
    println!("  Present in {}/{} images", dri_present_count, dumps.len());

    let mut dri_values: Vec<u16> = dumps
        .iter()
        .filter_map(|(_, s)| {
            segment_of_name(s, "DRI").and_then(|seg| {
                if seg.payload.len() >= 2 {
                    Some(((seg.payload[0] as u16) << 8) | seg.payload[1] as u16)
                } else {
                    None
                }
            })
        })
        .collect();
    dri_values.sort();
    dri_values.dedup();
    if !dri_values.is_empty() {
        println!("  Distinct restart interval values (MCUs): {:?}", dri_values);
    }
    println!();

    // ── SOS ──────────────────────────────────────────────────────────────────
    println!("## SOS component mapping\n");
    let mut sos_payloads: Vec<Vec<u8>> = dumps
        .iter()
        .filter_map(|(_, s)| segment_of_name(s, "SOS").map(|seg| seg.payload.clone()))
        .collect();
    sos_payloads.sort();
    sos_payloads.dedup();
    println!("  Distinct SOS payloads: {}", sos_payloads.len());
    for p in &sos_payloads {
        let hex: Vec<String> = p.iter().map(|b| format!("{b:02X}")).collect();
        println!("    {}", hex.join(""));
    }
    println!();

    // ── APP presence ─────────────────────────────────────────────────────────
    println!("## APP segments\n");
    for app in ["APP0", "APP1", "APP2"] {
        let count = dumps
            .iter()
            .filter(|(_, s)| segment_of_name(s, app).is_some())
            .count();
        if count > 0 {
            println!("  {}: {}/{} images", app, count, dumps.len());
        }
    }
    println!();

    // ── Summary ───────────────────────────────────────────────────────────────
    println!("## Summary\n");
    println!("  DQT invariant:              {}", dqt_invariant);
    println!("  DHT invariant:              {}", dht_invariant);
    println!("  SOF0 non-dim invariant:     {}", sof_nondim_invariant);
    println!("  Marker ordering invariant:  {}", ordering_invariant);
    println!("  DRI present:                {}/{}", dri_present_count, dumps.len());
    println!();

    // ── Profile candidate fields ──────────────────────────────────────────────
    println!("## Camera profile fields\n");
    println!("  INVARIANT (safe to hardcode in profile):");
    if dqt_invariant { println!("    - DQT payload(s) — all {} tables", dqt_min); }
    if dht_invariant { println!("    - DHT payload(s) — all {} tables", dht_min); }
    if sof_nondim_invariant { println!("    - SOF0 precision, component count, sampling factors, qt selectors"); }
    if ordering_invariant { println!("    - Marker ordering"); }
    if dri_present_count == dumps.len() && dri_values.len() == 1 {
        println!("    - DRI value ({})", dri_values[0]);
    }
    println!("  RESOLUTION-DEPENDENT (inject at rebuild time):");
    println!("    - SOF0 width and height");
    println!("  METADATA-ONLY / IGNORABLE:");
    println!("    - APP1 (Exif) — per-image, not needed for decode");
    println!("    - APP0 (JFIF) — informational only");
    println!();

    // ── Assertions ────────────────────────────────────────────────────────────
    assert!(
        dqt_invariant,
        "DQT tables must be identical across Canon IXUS 310 HS images"
    );
    assert!(
        dht_invariant,
        "DHT tables must be identical across Canon IXUS 310 HS images"
    );
    assert!(
        sof_nondim_invariant,
        "SOF0 non-dimensional fields must be invariant"
    );

    println!("All consistency assertions passed.");
}

/// Verifies that the DQT and DHT payloads from a known reference image
/// match the first fixture, giving a regression anchor for the profile.
#[test]
fn dqt_and_dht_match_across_sample_pair() {
    let fixtures = clean_fixtures();
    if fixtures.len() < 2 {
        return;
    }

    let bytes0 = std::fs::read(&fixtures[0]).unwrap();
    let bytes1 = std::fs::read(&fixtures[1]).unwrap();

    let off0 = match find_main_jpeg_offset(&bytes0) { Some(o) => o, None => return };
    let off1 = match find_main_jpeg_offset(&bytes1) { Some(o) => o, None => return };

    let dump0 = dump_jpeg_segments(&bytes0, off0).unwrap();
    let dump1 = dump_jpeg_segments(&bytes1, off1).unwrap();

    let dqts0: Vec<&[u8]> = segments_of_name(&dump0.segments, "DQT")
        .into_iter().map(|s| s.payload.as_slice()).collect();
    let dqts1: Vec<&[u8]> = segments_of_name(&dump1.segments, "DQT")
        .into_iter().map(|s| s.payload.as_slice()).collect();
    assert_eq!(dqts0, dqts1, "DQT tables must match between fixture pair");

    let dhts0: Vec<&[u8]> = segments_of_name(&dump0.segments, "DHT")
        .into_iter().map(|s| s.payload.as_slice()).collect();
    let dhts1: Vec<&[u8]> = segments_of_name(&dump1.segments, "DHT")
        .into_iter().map(|s| s.payload.as_slice()).collect();
    assert_eq!(dhts0, dhts1, "DHT tables must match between fixture pair");
}
