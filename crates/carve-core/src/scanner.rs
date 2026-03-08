use crate::jpeg::candidate::{Candidate, RecoveryStatus};

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
}
