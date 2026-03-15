// JPEG validation, truncation policy, and confidence scoring
use super::candidate::RecoveryStatus;
use super::entropy::{scan_entropy_stream, EntropyResult, EntropyTerminationReason};
use super::parse::{parse_until_sos, parse_until_sos_no_soi, PreSosResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationOptions {
    pub allow_truncated: bool,
    pub max_size: usize,
    pub patch_eoi: PatchEoiPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchEoiPolicy {
    None,
    Append,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ValidatedCandidate {
    pub start: usize,
    pub end: usize, // exclusive
    pub status: RecoveryStatus,
    pub patched_eoi: bool,
    pub missing_soi: bool,
    pub confidence_score: f32,
    pub has_exif: bool,
    pub has_dqt: bool,
    pub has_dht: bool,
    pub width: Option<u16>,
    pub height: Option<u16>,
    pub is_progressive: Option<bool>,
    /// The last RST0–RST7 marker byte seen in the entropy stream, if any.
    ///
    /// When a candidate is truncated at a cluster boundary, this value
    /// identifies which RST marker the stream ended on. The expected next
    /// RST marker in a continuation cluster is `next_rst(last_rst_marker)`.
    pub last_rst_marker: Option<u8>,
}

/// End-to-end validation pipeline: parse → entropy scan → validated candidate.
///
/// Calls `parse_until_sos`, `scan_entropy_stream`, and `validate_from_parts` in sequence.
/// Returns `None` when the bytes at `start` cannot produce a valid candidate.
pub fn validate_candidate(
    bytes: &[u8],
    start: usize,
    options: ValidationOptions,
) -> Option<ValidatedCandidate> {
    let max_end = bytes.len().min(start.saturating_add(options.max_size));
    let pre_sos = parse_until_sos(bytes, start, options.max_size).ok()?;
    let entropy = scan_entropy_stream(bytes, pre_sos.scan_start, max_end);
    validate_from_parts(start, &pre_sos, &entropy, options)
}

/// Validate a candidate that starts without an SOI marker.
///
/// Calls `parse_until_sos_no_soi` instead of `parse_until_sos`, applies a −10
/// confidence penalty, and sets `missing_soi: true` on the result. The SOI
/// prefix (`FF D8`) must be synthesized at extraction time.
pub fn validate_headerless_candidate(
    bytes: &[u8],
    start: usize,
    options: ValidationOptions,
) -> Option<ValidatedCandidate> {
    let max_end = bytes.len().min(start.saturating_add(options.max_size));
    let pre_sos = parse_until_sos_no_soi(bytes, start, options.max_size).ok()?;
    let entropy = scan_entropy_stream(bytes, pre_sos.scan_start, max_end);
    let mut candidate = validate_from_parts(start, &pre_sos, &entropy, options)?;
    candidate.missing_soi = true;
    candidate.confidence_score = (candidate.confidence_score - 0.10).max(0.0);
    Some(candidate)
}

/// Validate a carved JPEG candidate from pre-computed parse + entropy results.
///
/// Truncated policy (ticket 4.1):
/// - If EOI is not found, emit `Truncated` only when `allow_truncated=true`.
/// - Truncated ranges end at entropy boundary or max_size, whichever comes first.
/// EOI patching policy (ticket 4.2):
/// - If candidate is truncated and `patch_eoi == Append`, set `patched_eoi=true`.
pub fn validate_from_parts(
    start: usize,
    pre_sos: &PreSosResult,
    entropy: &EntropyResult,
    options: ValidationOptions,
) -> Option<ValidatedCandidate> {
    if options.max_size == 0 || pre_sos.scan_start <= start {
        return None;
    }

    // Entropy scanner reports marker boundary at the 0xFF byte.
    // For EOI, include the full FF D9 marker bytes.
    let raw_end = match entropy.reason {
        EntropyTerminationReason::Eoi => entropy.end_offset.saturating_add(2),
        _ => entropy.end_offset,
    };

    let max_end = start.saturating_add(options.max_size);
    let end = raw_end.min(max_end);
    if end <= start {
        return None;
    }

    let is_recovered = matches!(entropy.reason, EntropyTerminationReason::Eoi) && end == raw_end;
    if !is_recovered && !options.allow_truncated {
        return None;
    }

    let status = if is_recovered {
        RecoveryStatus::Recovered
    } else {
        RecoveryStatus::Truncated
    };
    let confidence_score = compute_confidence_score(pre_sos, status);
    let patched_eoi = matches!(status, RecoveryStatus::Truncated)
        && matches!(options.patch_eoi, PatchEoiPolicy::Append);

    Some(ValidatedCandidate {
        start,
        end,
        status,
        patched_eoi,
        missing_soi: false,
        confidence_score,
        has_exif: pre_sos.has_exif,
        has_dqt: pre_sos.has_dqt,
        has_dht: pre_sos.has_dht,
        width: pre_sos.width,
        height: pre_sos.height,
        is_progressive: pre_sos.is_progressive,
        last_rst_marker: entropy.last_rst_marker,
    })
}

fn compute_confidence_score(pre_sos: &PreSosResult, status: RecoveryStatus) -> f32 {
    let mut points: i32 = 0;

    // `validate_candidate` is called only after pre-SOS validation, so SOI/SOS are valid.
    points += 20; // valid SOI
    points += 20; // has SOS

    if pre_sos.has_exif {
        points += 20;
    }

    let has_sof = pre_sos.width.is_some() && pre_sos.height.is_some();
    if has_sof {
        points += 30;
    }

    if matches!(status, RecoveryStatus::Recovered) {
        points += 10; // normal EOI
    } else {
        points -= 15; // truncated
    }

    points = points.clamp(0, 100);
    points as f32 / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pre_sos(scan_start: usize) -> PreSosResult {
        PreSosResult {
            sos_marker_pos: scan_start.saturating_sub(8),
            scan_start,
            segments_parsed: 3,
            has_exif: true,
            has_dqt: true,
            has_dht: false,
            width: Some(640),
            height: Some(480),
            is_progressive: Some(false),
        }
    }

    fn entropy(reason: EntropyTerminationReason, end_offset: usize) -> EntropyResult {
        EntropyResult {
            end_offset,
            reason,
            restart_markers_seen: 0,
            last_rst_marker: None,
        }
    }

    #[test]
    fn recovered_candidate_is_emitted_even_if_truncated_not_allowed() {
        let candidate = validate_from_parts(
            100,
            &pre_sos(150),
            &entropy(EntropyTerminationReason::Eoi, 200),
            ValidationOptions {
                allow_truncated: false,
                max_size: 10_000,
                patch_eoi: PatchEoiPolicy::Append,
            },
        )
        .unwrap();

        assert_eq!(candidate.start, 100);
        assert_eq!(candidate.end, 202); // include FF D9
        assert_eq!(candidate.status, RecoveryStatus::Recovered);
        assert!(!candidate.patched_eoi);
        assert!((candidate.confidence_score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn truncated_candidate_requires_allow_truncated() {
        let out = validate_from_parts(
            100,
            &pre_sos(120),
            &entropy(
                EntropyTerminationReason::UnexpectedMarker { marker: 0xC0 },
                250,
            ),
            ValidationOptions {
                allow_truncated: false,
                max_size: 10_000,
                patch_eoi: PatchEoiPolicy::Append,
            },
        );
        assert!(out.is_none());
    }

    #[test]
    fn truncated_candidate_emits_when_allowed() {
        let candidate = validate_from_parts(
            100,
            &pre_sos(120),
            &entropy(EntropyTerminationReason::OutOfBounds, 280),
            ValidationOptions {
                allow_truncated: true,
                max_size: 10_000,
                patch_eoi: PatchEoiPolicy::None,
            },
        )
        .unwrap();

        assert_eq!(candidate.start, 100);
        assert_eq!(candidate.end, 280);
        assert_eq!(candidate.status, RecoveryStatus::Truncated);
        assert!(!candidate.patched_eoi);
        assert!((candidate.confidence_score - 0.75).abs() < f32::EPSILON);
        assert!(candidate.has_exif);
        assert_eq!(candidate.width, Some(640));
        assert_eq!(candidate.height, Some(480));
    }

    #[test]
    fn truncated_candidate_is_bounded_by_max_size() {
        let candidate = validate_from_parts(
            100,
            &pre_sos(120),
            &entropy(EntropyTerminationReason::OutOfBounds, 500),
            ValidationOptions {
                allow_truncated: true,
                max_size: 50,
                patch_eoi: PatchEoiPolicy::Append,
            },
        )
        .unwrap();

        assert_eq!(candidate.end, 150);
        assert_eq!(candidate.status, RecoveryStatus::Truncated);
        assert!(candidate.patched_eoi);
    }

    #[test]
    fn truncated_candidate_sets_patched_eoi_when_append_mode() {
        let candidate = validate_from_parts(
            100,
            &pre_sos(120),
            &entropy(EntropyTerminationReason::OutOfBounds, 280),
            ValidationOptions {
                allow_truncated: true,
                max_size: 10_000,
                patch_eoi: PatchEoiPolicy::Append,
            },
        )
        .unwrap();

        assert_eq!(candidate.status, RecoveryStatus::Truncated);
        assert!(candidate.patched_eoi);
    }

    #[test]
    fn recovered_candidate_never_sets_patched_eoi() {
        let candidate = validate_from_parts(
            100,
            &pre_sos(150),
            &entropy(EntropyTerminationReason::Eoi, 200),
            ValidationOptions {
                allow_truncated: false,
                max_size: 10_000,
                patch_eoi: PatchEoiPolicy::Append,
            },
        )
        .unwrap();

        assert_eq!(candidate.status, RecoveryStatus::Recovered);
        assert!(!candidate.patched_eoi);
    }

    #[test]
    fn confidence_model_applies_weights_and_clamps() {
        let mut with_no_signals = pre_sos(120);
        with_no_signals.has_exif = false;
        with_no_signals.width = None;
        with_no_signals.height = None;

        // SOI + SOS + truncated penalty = 0.25
        let low = compute_confidence_score(&with_no_signals, RecoveryStatus::Truncated);
        assert!((low - 0.25).abs() < f32::EPSILON);

        // SOI + SOS + EXIF + SOF + EOI = 1.0
        let high = compute_confidence_score(&pre_sos(120), RecoveryStatus::Recovered);
        assert!((high - 1.0).abs() < f32::EPSILON);
    }

    // --- End-to-end tests for validate_candidate (orchestrating function) ---

    fn make_segment_bytes(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        let mut v = vec![0xFF, marker, (len >> 8) as u8, len as u8];
        v.extend_from_slice(payload);
        v
    }

    fn make_valid_jpeg_bytes() -> Vec<u8> {
        use super::super::markers;
        let mut buf = vec![0xFF, markers::SOI];
        // DQT
        let mut dqt = vec![0x00u8];
        dqt.extend_from_slice(&[16u8; 64]);
        buf.extend(make_segment_bytes(markers::DQT, &dqt));
        // SOF0: height=240, width=320, 3 components
        let sof = [0x08, 0x00, 0xF0, 0x01, 0x40, 0x03,
                   0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01];
        buf.extend(make_segment_bytes(markers::SOF0, &sof));
        // SOS
        let sos = [0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00];
        buf.extend(make_segment_bytes(markers::SOS, &sos));
        // entropy + EOI
        buf.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        buf.extend_from_slice(&[0xFF, 0xD9]);
        buf
    }

    fn make_truncated_jpeg_bytes() -> Vec<u8> {
        use super::super::markers;
        let mut buf = vec![0xFF, markers::SOI];
        let mut dqt = vec![0x00u8];
        dqt.extend_from_slice(&[16u8; 64]);
        buf.extend(make_segment_bytes(markers::DQT, &dqt));
        let sof = [0x08, 0x00, 0x78, 0x00, 0xA0, 0x03,
                   0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01];
        buf.extend(make_segment_bytes(markers::SOF0, &sof));
        let sos = [0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00];
        buf.extend(make_segment_bytes(markers::SOS, &sos));
        // entropy only, no EOI
        buf.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x12, 0x34]);
        buf
    }

    #[test]
    fn end_to_end_valid_jpeg_returns_recovered() {
        let data = make_valid_jpeg_bytes();
        let candidate = validate_candidate(
            &data,
            0,
            ValidationOptions {
                allow_truncated: false,
                max_size: data.len(),
                patch_eoi: PatchEoiPolicy::None,
            },
        )
        .expect("valid JPEG should produce a candidate");

        assert_eq!(candidate.status, RecoveryStatus::Recovered);
        assert_eq!(candidate.start, 0);
        assert_eq!(candidate.end, data.len());
        assert!(!candidate.patched_eoi);
        assert_eq!(candidate.width, Some(320));
        assert_eq!(candidate.height, Some(240));
    }

    #[test]
    fn end_to_end_truncated_jpeg_strict_mode_returns_none() {
        let data = make_truncated_jpeg_bytes();
        let result = validate_candidate(
            &data,
            0,
            ValidationOptions {
                allow_truncated: false,
                max_size: data.len(),
                patch_eoi: PatchEoiPolicy::None,
            },
        );
        assert!(result.is_none());
    }

    #[test]
    fn end_to_end_truncated_jpeg_lenient_mode_returns_truncated() {
        let data = make_truncated_jpeg_bytes();
        let candidate = validate_candidate(
            &data,
            0,
            ValidationOptions {
                allow_truncated: true,
                max_size: data.len(),
                patch_eoi: PatchEoiPolicy::Append,
            },
        )
        .expect("lenient mode should emit truncated candidate");

        assert_eq!(candidate.status, RecoveryStatus::Truncated);
        assert!(candidate.patched_eoi);
        assert_eq!(candidate.start, 0);
        assert_eq!(candidate.end, data.len());
    }

    #[test]
    fn end_to_end_invalid_bytes_returns_none() {
        let data = vec![0x00u8; 64];
        let result = validate_candidate(
            &data,
            0,
            ValidationOptions {
                allow_truncated: true,
                max_size: data.len(),
                patch_eoi: PatchEoiPolicy::None,
            },
        );
        assert!(result.is_none());
    }

    #[test]
    fn end_to_end_nonzero_start_offset() {
        let mut data = vec![0xDEu8; 32]; // garbage prefix
        data.extend(make_valid_jpeg_bytes());
        let start = 32;
        let candidate = validate_candidate(
            &data,
            start,
            ValidationOptions {
                allow_truncated: false,
                max_size: data.len(),
                patch_eoi: PatchEoiPolicy::None,
            },
        )
        .expect("should recover JPEG at nonzero offset");

        assert_eq!(candidate.start, start);
        assert_eq!(candidate.end, data.len());
        assert_eq!(candidate.status, RecoveryStatus::Recovered);
        assert!(!candidate.missing_soi);
    }

    fn make_headerless_jpeg_bytes() -> Vec<u8> {
        use super::super::markers;
        // Same structure as make_valid_jpeg_bytes() but without the leading SOI
        let mut buf = Vec::new();
        let mut dqt = vec![0x00u8];
        dqt.extend_from_slice(&[16u8; 64]);
        buf.extend(make_segment_bytes(markers::DQT, &dqt));
        let sof = [0x08, 0x00, 0xF0, 0x01, 0x40, 0x03,
                   0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01];
        buf.extend(make_segment_bytes(markers::SOF0, &sof));
        let sos = [0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00];
        buf.extend(make_segment_bytes(markers::SOS, &sos));
        buf.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        buf.extend_from_slice(&[0xFF, 0xD9]);
        buf
    }

    #[test]
    fn validate_headerless_candidate_sets_missing_soi() {
        let data = make_headerless_jpeg_bytes();
        let candidate = validate_headerless_candidate(
            &data,
            0,
            ValidationOptions {
                allow_truncated: false,
                max_size: data.len(),
                patch_eoi: PatchEoiPolicy::None,
            },
        )
        .expect("headerless JPEG should produce a candidate");

        assert!(candidate.missing_soi);
        assert_eq!(candidate.status, RecoveryStatus::Recovered);
        assert_eq!(candidate.start, 0);
        assert_eq!(candidate.end, data.len());
        assert_eq!(candidate.width, Some(320));
        assert_eq!(candidate.height, Some(240));
    }

    #[test]
    fn validate_headerless_candidate_confidence_lower_than_soi_version() {
        let headerless = make_headerless_jpeg_bytes();
        let headerless_candidate = validate_headerless_candidate(
            &headerless,
            0,
            ValidationOptions {
                allow_truncated: false,
                max_size: headerless.len(),
                patch_eoi: PatchEoiPolicy::None,
            },
        )
        .unwrap();

        // Build the equivalent with SOI
        let mut with_soi = vec![0xFF, super::super::markers::SOI];
        with_soi.extend_from_slice(&headerless);
        let soi_candidate = validate_candidate(
            &with_soi,
            0,
            ValidationOptions {
                allow_truncated: false,
                max_size: with_soi.len(),
                patch_eoi: PatchEoiPolicy::None,
            },
        )
        .unwrap();

        assert!(
            headerless_candidate.confidence_score < soi_candidate.confidence_score,
            "headerless confidence ({}) should be lower than SOI confidence ({})",
            headerless_candidate.confidence_score,
            soi_candidate.confidence_score,
        );
    }

    #[test]
    fn validate_headerless_candidate_rejects_noise() {
        let data = vec![0x00u8; 64];
        let result = validate_headerless_candidate(
            &data,
            0,
            ValidationOptions {
                allow_truncated: true,
                max_size: data.len(),
                patch_eoi: PatchEoiPolicy::None,
            },
        );
        assert!(result.is_none());
    }
}
