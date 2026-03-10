use crate::jpeg::candidate::{Candidate, RecoveryStatus};
use crate::jpeg::markers;
use crate::jpeg::validate::{validate_candidate, ValidatedCandidate, ValidationOptions};

/// Scan `bytes` for all SOI markers (FF D8) and return their offsets in order.
fn find_soi_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let len = bytes.len().saturating_sub(1);
    let mut i = 0;
    while i < len {
        if bytes[i] == 0xFF && bytes[i + 1] == markers::SOI {
            offsets.push(i);
            i += 2;
        } else {
            i += 1;
        }
    }
    offsets
}

/// Attempt validation at every SOI offset and collect successful candidates.
///
/// Each SOI is passed to `validate_candidate`; failures are silently skipped.
/// Results are returned in offset order (deterministic).
pub fn recover_candidates(bytes: &[u8], options: ValidationOptions) -> Vec<ValidatedCandidate> {
    find_soi_offsets(bytes)
        .into_iter()
        .filter_map(|start| validate_candidate(bytes, start, options))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlapOptions {
    pub keep_overlaps: bool,
}

impl Default for OverlapOptions {
    fn default() -> Self {
        Self {
            keep_overlaps: false,
        }
    }
}

/// Apply overlap policy to validated candidates.
///
/// Default behavior suppresses overlaps. Setting `keep_overlaps=true`
/// returns candidates unchanged.
pub fn apply_overlap_policy(candidates: Vec<Candidate>, options: OverlapOptions) -> Vec<Candidate> {
    if options.keep_overlaps {
        candidates
    } else {
        suppress_overlapping_candidates(candidates)
    }
}

/// Suppress overlapping candidate ranges deterministically.
///
/// Rules:
/// - Sort by start ascending, then end ascending.
/// - Group connected overlaps into clusters.
/// - For each cluster, emit the strongest candidate using deterministic ranking:
///   complete > truncated, larger span preferred, then earlier start.
pub fn suppress_overlapping_candidates(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| a.end.cmp(&b.end))
            .then_with(|| status_rank(a.status).cmp(&status_rank(b.status)))
    });

    let mut emitted: Vec<Candidate> = Vec::with_capacity(candidates.len());
    let mut cluster_best: Option<Candidate> = None;
    let mut cluster_end: usize = 0;

    for candidate in candidates {
        match cluster_best {
            None => {
                cluster_end = candidate.end;
                cluster_best = Some(candidate);
            }
            Some(best) => {
                if candidate.start >= cluster_end {
                    emitted.push(best);
                    cluster_end = candidate.end;
                    cluster_best = Some(candidate);
                    continue;
                }

                cluster_end = cluster_end.max(candidate.end);
                if candidate_is_stronger(candidate, best) {
                    cluster_best = Some(candidate);
                }
            }
        }
    }

    if let Some(best) = cluster_best {
        emitted.push(best);
    }

    emitted
}

#[inline]
fn status_rank(status: RecoveryStatus) -> u8 {
    match status {
        RecoveryStatus::Recovered => 0,
        RecoveryStatus::Truncated => 1,
    }
}

#[inline]
fn is_complete(candidate: Candidate) -> bool {
    matches!(candidate.status, RecoveryStatus::Recovered)
}

#[inline]
fn span(candidate: Candidate) -> usize {
    candidate.end.saturating_sub(candidate.start)
}

fn candidate_is_stronger(lhs: Candidate, rhs: Candidate) -> bool {
    if is_complete(lhs) != is_complete(rhs) {
        return is_complete(lhs);
    }

    let lhs_span = span(lhs);
    let rhs_span = span(rhs);
    if lhs_span != rhs_span {
        return lhs_span > rhs_span;
    }

    if lhs.start != rhs.start {
        return lhs.start < rhs.start;
    }

    if lhs.end != rhs.end {
        return lhs.end < rhs.end;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(start: usize, end: usize, status: RecoveryStatus) -> Candidate {
        Candidate { start, end, status }
    }

    #[test]
    fn suppresses_nested_candidates() {
        let input = vec![
            c(10, 100, RecoveryStatus::Recovered),
            c(20, 80, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(10, 100, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn suppresses_partially_overlapping_candidates() {
        let input = vec![
            c(0, 50, RecoveryStatus::Recovered),
            c(40, 90, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(0, 50, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn keeps_non_overlapping_candidates() {
        let input = vec![
            c(0, 50, RecoveryStatus::Recovered),
            c(50, 100, RecoveryStatus::Recovered),
            c(120, 150, RecoveryStatus::Truncated),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(
            out,
            vec![
                c(0, 50, RecoveryStatus::Recovered),
                c(50, 100, RecoveryStatus::Recovered),
                c(120, 150, RecoveryStatus::Truncated)
            ]
        );
    }

    #[test]
    fn identical_ranges_emit_only_one() {
        let input = vec![
            c(10, 40, RecoveryStatus::Recovered),
            c(10, 40, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(10, 40, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn identical_ranges_prefers_complete_over_truncated() {
        let input = vec![
            c(10, 40, RecoveryStatus::Truncated),
            c(10, 40, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(10, 40, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn same_start_overlap_prefers_complete() {
        let input = vec![
            c(10, 20, RecoveryStatus::Truncated),
            c(10, 100, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(10, 100, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn overlap_prefers_complete_even_with_later_start() {
        let input = vec![
            c(10, 100, RecoveryStatus::Truncated),
            c(20, 80, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(20, 80, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn overlap_does_not_replace_complete_with_truncated() {
        let input = vec![
            c(10, 100, RecoveryStatus::Recovered),
            c(20, 80, RecoveryStatus::Truncated),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(10, 100, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn nested_candidates_prefer_larger_span() {
        let input = vec![
            c(10, 120, RecoveryStatus::Recovered),
            c(20, 80, RecoveryStatus::Recovered),
            c(30, 70, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(10, 120, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn connected_overlap_cluster_selects_single_strongest_candidate() {
        let input = vec![
            c(0, 10, RecoveryStatus::Recovered),
            c(5, 20, RecoveryStatus::Recovered),
            c(15, 40, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(15, 40, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn same_status_and_span_prefers_earlier_start() {
        let input = vec![
            c(10, 30, RecoveryStatus::Recovered),
            c(12, 32, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(out, vec![c(10, 30, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn ordering_is_deterministic_for_unsorted_input() {
        let input = vec![
            c(100, 120, RecoveryStatus::Recovered),
            c(10, 90, RecoveryStatus::Recovered),
            c(90, 100, RecoveryStatus::Recovered),
            c(10, 90, RecoveryStatus::Recovered),
            c(30, 50, RecoveryStatus::Recovered),
        ];
        let out = suppress_overlapping_candidates(input);
        assert_eq!(
            out,
            vec![
                c(10, 90, RecoveryStatus::Recovered),
                c(90, 100, RecoveryStatus::Recovered),
                c(100, 120, RecoveryStatus::Recovered)
            ]
        );
    }

    #[test]
    fn default_mode_suppresses_overlaps() {
        let input = vec![
            c(0, 50, RecoveryStatus::Recovered),
            c(40, 90, RecoveryStatus::Recovered),
        ];
        let out = apply_overlap_policy(input, OverlapOptions::default());
        assert_eq!(out, vec![c(0, 50, RecoveryStatus::Recovered)]);
    }

    #[test]
    fn keep_overlaps_mode_emits_all_candidates() {
        let input = vec![
            c(0, 50, RecoveryStatus::Recovered),
            c(40, 90, RecoveryStatus::Recovered),
        ];
        let out = apply_overlap_policy(
            input.clone(),
            OverlapOptions {
                keep_overlaps: true,
            },
        );
        assert_eq!(out, input);
    }

    // --- find_soi_offsets tests ---

    #[test]
    fn find_soi_offsets_empty() {
        assert!(find_soi_offsets(&[]).is_empty());
    }

    #[test]
    fn find_soi_offsets_single() {
        let data = [0xFF, markers::SOI, 0x00, 0x00];
        assert_eq!(find_soi_offsets(&data), vec![0]);
    }

    #[test]
    fn find_soi_offsets_multiple() {
        let mut data = vec![0x00u8; 10];
        data[2] = 0xFF; data[3] = markers::SOI;
        data[7] = 0xFF; data[8] = markers::SOI;
        assert_eq!(find_soi_offsets(&data), vec![2, 7]);
    }

    #[test]
    fn find_soi_offsets_no_soi_in_noise() {
        let data = vec![0xAB, 0xCD, 0xEF, 0xFF, 0x00, 0xFF, 0xD7];
        assert!(find_soi_offsets(&data).is_empty());
    }

    #[test]
    fn find_soi_at_last_byte_not_counted() {
        // FF at the very last byte has no following byte — must not panic or count it
        let data = [0x00, 0xFF];
        assert!(find_soi_offsets(&data).is_empty());
    }

    // --- recover_candidates tests ---

    fn make_segment_bytes(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        let mut v = vec![0xFF, marker, (len >> 8) as u8, len as u8];
        v.extend_from_slice(payload);
        v
    }

    fn make_valid_jpeg() -> Vec<u8> {
        let mut buf = vec![0xFF, markers::SOI];
        let mut dqt = vec![0x00u8]; dqt.extend_from_slice(&[16u8; 64]);
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

    fn default_options(data_len: usize) -> ValidationOptions {
        use crate::jpeg::validate::PatchEoiPolicy;
        ValidationOptions { allow_truncated: false, max_size: data_len, patch_eoi: PatchEoiPolicy::None }
    }

    #[test]
    fn recover_candidates_empty_bytes_returns_empty() {
        let result = recover_candidates(&[], default_options(0));
        assert!(result.is_empty());
    }

    #[test]
    fn recover_candidates_noise_returns_empty() {
        let data = vec![0xABu8; 256];
        let result = recover_candidates(&data, default_options(data.len()));
        assert!(result.is_empty());
    }

    #[test]
    fn recover_candidates_single_valid_jpeg() {
        let data = make_valid_jpeg();
        let result = recover_candidates(&data, default_options(data.len()));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].end, data.len());
        assert_eq!(result[0].status, RecoveryStatus::Recovered);
    }

    #[test]
    fn recover_candidates_invalid_soi_is_skipped() {
        // SOI followed by garbage — parse fails, no candidate
        let mut data = vec![0xFF, markers::SOI];
        data.extend_from_slice(&[0x00u8; 32]);
        let result = recover_candidates(&data, default_options(data.len()));
        assert!(result.is_empty());
    }

    #[test]
    fn recover_candidates_two_jpegs_concatenated() {
        let jpeg = make_valid_jpeg();
        let mut data = jpeg.clone();
        data.extend_from_slice(&jpeg);
        let result = recover_candidates(&data, default_options(data.len()));
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[1].start, jpeg.len());
    }

    #[test]
    fn recover_candidates_results_in_offset_order() {
        let jpeg = make_valid_jpeg();
        let mut data = vec![0xFFu8; 16]; // garbage prefix
        data.extend_from_slice(&jpeg);
        let result = recover_candidates(&data, default_options(data.len()));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start, 16);
    }
}
