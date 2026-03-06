use crate::jpeg::candidate::{Candidate, RecoveryStatus};

/// Suppress overlapping candidate ranges deterministically.
///
/// Rules:
/// - Sort by start ascending, then end ascending.
/// - Emit only ranges that do not overlap the last emitted range.
/// - For equal-start overlaps, prefer complete over truncated.
pub fn suppress_overlapping_candidates(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| a.end.cmp(&b.end))
            .then_with(|| status_rank(a.status).cmp(&status_rank(b.status)))
    });

    let mut emitted: Vec<Candidate> = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        match emitted.last_mut() {
            None => emitted.push(candidate),
            Some(last) => {
                if candidate.start >= last.end {
                    emitted.push(candidate);
                    continue;
                }

                // Edge case: overlapping complete candidate should replace truncated.
                if is_complete(candidate) && !is_complete(*last) {
                    *last = candidate;
                }
            }
        }
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
}
