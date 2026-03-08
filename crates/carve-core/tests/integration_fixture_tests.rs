//! Integration fixture tests.
//!
//! Builds synthetic JPEG fixtures in-memory and exercises the full
//! parse → entropy-scan → validate pipeline.

use carve_core::jpeg::candidate::RecoveryStatus;
use carve_core::jpeg::entropy::scan_entropy_stream;
use carve_core::jpeg::markers;
use carve_core::jpeg::parse::parse_until_sos;
use carve_core::jpeg::validate::{validate_candidate, PatchEoiPolicy, ValidationOptions};

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

fn make_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() + 2) as u16;
    let mut v = vec![0xFF, marker, (len >> 8) as u8, len as u8];
    v.extend_from_slice(payload);
    v
}

/// Valid JPEG: SOI + APP0(JFIF) + DQT + SOF0(320×240) + DHT + SOS + entropy + EOI
fn fixture_valid_jpeg() -> Vec<u8> {
    let mut buf = vec![0xFF, markers::SOI];

    // APP0 JFIF
    let mut jfif = b"JFIF\0".to_vec();
    jfif.extend_from_slice(&[1, 1, 0, 0, 72, 0, 72, 0, 0]);
    buf.extend(make_segment(0xE0, &jfif));

    // DQT (table 0, 64 bytes)
    let mut dqt = vec![0x00u8];
    dqt.extend_from_slice(&[16u8; 64]);
    buf.extend(make_segment(markers::DQT, &dqt));

    // SOF0: precision=8, height=240(0x00F0), width=320(0x0140), 3 components
    let sof = [
        0x08,
        0x00, 0xF0, // height 240
        0x01, 0x40, // width  320
        0x03,
        0x01, 0x22, 0x00,
        0x02, 0x11, 0x01,
        0x03, 0x11, 0x01,
    ];
    buf.extend(make_segment(markers::SOF0, &sof));

    // DHT (minimal)
    buf.extend(make_segment(markers::DHT, &[0u8; 20]));

    // SOS (3 components)
    let sos = [0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00];
    buf.extend(make_segment(markers::SOS, &sos));

    // Entropy data + EOI
    buf.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x12, 0x34]);
    buf.extend_from_slice(&[0xFF, 0xD9]); // EOI
    buf
}

/// Truncated JPEG: SOI + DQT + SOF0(160×120) + SOS + entropy, NO EOI.
fn fixture_truncated_jpeg() -> Vec<u8> {
    let mut buf = vec![0xFF, markers::SOI];

    // DQT (table 0, 64 bytes)
    let mut dqt = vec![0x00u8];
    dqt.extend_from_slice(&[16u8; 64]);
    buf.extend(make_segment(markers::DQT, &dqt));

    // SOF0: precision=8, height=120(0x0078), width=160(0x00A0), 3 components
    let sof = [
        0x08,
        0x00, 0x78, // height 120
        0x00, 0xA0, // width  160
        0x03,
        0x01, 0x22, 0x00,
        0x02, 0x11, 0x01,
        0x03, 0x11, 0x01,
    ];
    buf.extend(make_segment(markers::SOF0, &sof));

    // SOS
    let sos = [0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00];
    buf.extend(make_segment(markers::SOS, &sos));

    // Entropy data — deliberately no EOI (truncated)
    buf.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78]);
    buf
}

/// Corrupted segment length: APP0 length field claims to extend far past EOF.
fn fixture_corrupt_seg_len() -> Vec<u8> {
    let mut buf = vec![0xFF, markers::SOI];
    // APP0 header with length = 0x7FFF = 32767, but only 8 payload bytes follow.
    buf.extend_from_slice(&[0xFF, 0xE0, 0x7F, 0xFF]);
    buf.extend_from_slice(&[0x00u8; 8]);
    buf
}

/// 100 zero bytes with an SOI marker planted at offset 50; the bytes after the
/// SOI are all zeros and will not parse as a valid JPEG header.
fn fixture_noise_with_embedded_soi() -> Vec<u8> {
    let mut buf = vec![0x00u8; 100];
    buf[50] = 0xFF;
    buf[51] = markers::SOI;
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Valid JPEG fixture: pipeline succeeds, single Recovered candidate, correct metadata.
#[test]
fn valid_jpeg_fixture_recovers_complete_candidate() {
    let data = fixture_valid_jpeg();
    let start = 0;

    let pre_sos = parse_until_sos(&data, start, data.len())
        .expect("valid JPEG: parse_until_sos should succeed");

    // Metadata extracted from header
    assert_eq!(pre_sos.width, Some(320));
    assert_eq!(pre_sos.height, Some(240));
    assert_eq!(pre_sos.is_progressive, Some(false));
    assert!(pre_sos.has_dqt);
    assert!(pre_sos.has_dht);
    assert!(!pre_sos.has_exif);

    let entropy = scan_entropy_stream(&data, pre_sos.scan_start, data.len());

    let candidate = validate_candidate(
        start,
        &pre_sos,
        &entropy,
        ValidationOptions {
            allow_truncated: false,
            max_size: data.len(),
            patch_eoi: PatchEoiPolicy::None,
        },
    )
    .expect("valid JPEG: should emit a candidate");

    // Status: Recovered (EOI found)
    assert_eq!(candidate.status, RecoveryStatus::Recovered);
    assert!(!candidate.patched_eoi);
    assert_eq!(candidate.start, 0);
    assert_eq!(candidate.end, data.len());

    // Metadata forwarded to candidate
    assert_eq!(candidate.width, Some(320));
    assert_eq!(candidate.height, Some(240));
    assert!(candidate.has_dqt);
    assert!(candidate.has_dht);
    assert!(!candidate.has_exif);
}

/// Valid JPEG fixture: confidence = SOI(20) + SOS(20) + SOF(30) + EOI(10) = 0.80.
#[test]
fn valid_jpeg_fixture_confidence_score() {
    let data = fixture_valid_jpeg();
    let pre_sos = parse_until_sos(&data, 0, data.len()).unwrap();
    let entropy = scan_entropy_stream(&data, pre_sos.scan_start, data.len());

    let candidate = validate_candidate(
        0,
        &pre_sos,
        &entropy,
        ValidationOptions {
            allow_truncated: false,
            max_size: data.len(),
            patch_eoi: PatchEoiPolicy::None,
        },
    )
    .unwrap();

    assert!(
        (candidate.confidence_score - 0.80).abs() < f32::EPSILON,
        "expected confidence 0.80, got {}",
        candidate.confidence_score
    );
}

/// Truncated JPEG: strict mode suppresses candidate; lenient mode emits Truncated.
#[test]
fn truncated_jpeg_fixture_emits_truncated_candidate() {
    let data = fixture_truncated_jpeg();
    let start = 0;

    let pre_sos = parse_until_sos(&data, start, data.len())
        .expect("truncated JPEG: parse_until_sos should succeed");

    // Metadata
    assert_eq!(pre_sos.width, Some(160));
    assert_eq!(pre_sos.height, Some(120));
    assert_eq!(pre_sos.is_progressive, Some(false));
    assert!(pre_sos.has_dqt);
    assert!(!pre_sos.has_dht);
    assert!(!pre_sos.has_exif);

    let entropy = scan_entropy_stream(&data, pre_sos.scan_start, data.len());

    // Strict mode: no candidate emitted for truncated file
    assert!(
        validate_candidate(
            start,
            &pre_sos,
            &entropy,
            ValidationOptions {
                allow_truncated: false,
                max_size: data.len(),
                patch_eoi: PatchEoiPolicy::None,
            },
        )
        .is_none(),
        "strict mode should not emit a truncated candidate"
    );

    // Lenient mode: Truncated candidate emitted
    let candidate = validate_candidate(
        start,
        &pre_sos,
        &entropy,
        ValidationOptions {
            allow_truncated: true,
            max_size: data.len(),
            patch_eoi: PatchEoiPolicy::None,
        },
    )
    .expect("lenient mode: should emit truncated candidate");

    assert_eq!(candidate.status, RecoveryStatus::Truncated);
    assert!(!candidate.patched_eoi);
    assert_eq!(candidate.width, Some(160));
    assert_eq!(candidate.height, Some(120));
    assert!(candidate.has_dqt);
    assert!(!candidate.has_exif);

    // Truncated penalty keeps confidence below recovered threshold
    assert!(
        candidate.confidence_score < 0.80,
        "truncated confidence {} should be below 0.80",
        candidate.confidence_score
    );
}

/// Truncated JPEG with EOI patching: patched_eoi flag is set.
#[test]
fn truncated_jpeg_fixture_eoi_patch_flag() {
    let data = fixture_truncated_jpeg();
    let pre_sos = parse_until_sos(&data, 0, data.len()).unwrap();
    let entropy = scan_entropy_stream(&data, pre_sos.scan_start, data.len());

    let candidate = validate_candidate(
        0,
        &pre_sos,
        &entropy,
        ValidationOptions {
            allow_truncated: true,
            max_size: data.len(),
            patch_eoi: PatchEoiPolicy::Append,
        },
    )
    .unwrap();

    assert_eq!(candidate.status, RecoveryStatus::Truncated);
    assert!(candidate.patched_eoi, "EOI patching should be recorded");
}

/// Corrupted segment length: parse_until_sos returns an error.
#[test]
fn corrupt_seg_len_fixture_parse_fails() {
    let data = fixture_corrupt_seg_len();
    assert!(
        parse_until_sos(&data, 0, data.len()).is_err(),
        "corrupt segment length should cause a parse error"
    );
}

/// Noise with embedded SOI: the bytes after the SOI are invalid structure,
/// so parse_until_sos fails and no candidate is produced.
#[test]
fn noise_with_embedded_soi_yields_no_candidate() {
    let data = fixture_noise_with_embedded_soi();
    let soi_offset = 50;

    // The SOI at offset 50 is followed by all zeros — no valid marker stream.
    assert!(
        parse_until_sos(&data, soi_offset, data.len()).is_err(),
        "garbage after embedded SOI should fail to parse"
    );
}
