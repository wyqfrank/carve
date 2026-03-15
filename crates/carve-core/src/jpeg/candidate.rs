use super::entropy::{EntropyResult, EntropyTerminationReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStatus {
    Recovered,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub start: usize,
    pub end: usize, // exclusive
    pub status: RecoveryStatus,
}

/// Construct a validated candidate range from SOI `start` and entropy scan result.
///
/// - `max_size` is the maximum allowed candidate span in bytes.
/// - Returns `None` for invalid or zero-length ranges.
pub fn construct_candidate(start: usize, entropy: &EntropyResult, max_size: usize) -> Option<Candidate> {
    if max_size == 0 {
        return None;
    }

    // Entropy scanner returns marker boundary at the 0xFF byte.
    // Include the full EOI marker in recovered ranges.
    let raw_end = match entropy.reason {
        EntropyTerminationReason::Eoi => entropy.end_offset.saturating_add(2),
        _ => entropy.end_offset,
    };

    let max_end = start.saturating_add(max_size);
    let end = raw_end.min(max_end);
    if end <= start {
        return None;
    }

    let status = match entropy.reason {
        EntropyTerminationReason::Eoi if end == raw_end => RecoveryStatus::Recovered,
        _ => RecoveryStatus::Truncated,
    };

    Some(Candidate { start, end, status })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entropy(reason: EntropyTerminationReason, end_offset: usize) -> EntropyResult {
        EntropyResult {
            end_offset,
            reason,
            restart_markers_seen: 0,
            last_rst_marker: None,
        }
    }

    #[test]
    fn valid_jpeg_constructs_recovered_candidate() {
        let start = 100;
        let r = entropy(EntropyTerminationReason::Eoi, 250); // EOI marker starts at 250
        let c = construct_candidate(start, &r, 10_000).unwrap();

        assert_eq!(c.start, 100);
        assert_eq!(c.end, 252); // include FF D9
        assert_eq!(c.status, RecoveryStatus::Recovered);
    }

    #[test]
    fn truncated_candidate_is_flagged() {
        let start = 100;
        let r = entropy(
            EntropyTerminationReason::UnexpectedMarker { marker: 0xC0 },
            220,
        );
        let c = construct_candidate(start, &r, 10_000).unwrap();

        assert_eq!(c.start, 100);
        assert_eq!(c.end, 220);
        assert_eq!(c.status, RecoveryStatus::Truncated);
    }

    #[test]
    fn zero_length_ranges_are_rejected() {
        let start = 500;
        let r = entropy(EntropyTerminationReason::OutOfBounds, 500);
        assert!(construct_candidate(start, &r, 10_000).is_none());
    }

    #[test]
    fn range_is_bounded_by_max_size() {
        let start = 0;
        let r = entropy(EntropyTerminationReason::Eoi, 50);
        let c = construct_candidate(start, &r, 10).unwrap();

        assert_eq!(c.end, 10);
        assert_eq!(c.status, RecoveryStatus::Truncated);
    }
}
