// JPEG validation, truncation policy, and confidence scoring
use super::candidate::RecoveryStatus;
use super::entropy::{EntropyResult, EntropyTerminationReason};
use super::parse::PreSosResult;

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
    pub confidence_score: f32,
    pub has_exif: bool,
    pub has_dqt: bool,
    pub has_dht: bool,
    pub width: Option<u16>,
    pub height: Option<u16>,
    pub is_progressive: Option<bool>,
}

/// Validate a carved JPEG candidate after pre-SOS parse + entropy scan.
///
/// Truncated policy (ticket 4.1):
/// - If EOI is not found, emit `Truncated` only when `allow_truncated=true`.
/// - Truncated ranges end at entropy boundary or max_size, whichever comes first.
/// EOI patching policy (ticket 4.2):
/// - If candidate is truncated and `patch_eoi == Append`, set `patched_eoi=true`.
pub fn validate_candidate(
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
        confidence_score,
        has_exif: pre_sos.has_exif,
        has_dqt: pre_sos.has_dqt,
        has_dht: pre_sos.has_dht,
        width: pre_sos.width,
        height: pre_sos.height,
        is_progressive: pre_sos.is_progressive,
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
        }
    }

    #[test]
    fn recovered_candidate_is_emitted_even_if_truncated_not_allowed() {
        let candidate = validate_candidate(
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
        let out = validate_candidate(
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
        let candidate = validate_candidate(
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
        let candidate = validate_candidate(
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
        let candidate = validate_candidate(
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
        let candidate = validate_candidate(
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
}
