/// Position and value of a single RST marker found in the stream.
#[derive(Debug, Clone, PartialEq)]
pub struct RestartMarkerInfo {
    /// Byte offset of the 0xFF byte within the scanned buffer.
    pub offset: usize,
    /// Marker byte value: 0xD0–0xD7 (RST0–RST7).
    pub marker: u8,
}

/// Summary of RST markers found across an entropy stream.
#[derive(Debug, Clone)]
pub struct RestartScanSummary {
    /// Total number of RST markers found.
    pub count: u32,
    /// Each RST marker's position and value, in order.
    pub markers: Vec<RestartMarkerInfo>,
    /// Byte gaps between consecutive RST markers (empty when count < 2).
    pub intervals: Vec<usize>,
    /// Mean interval in bytes (None when count < 2).
    pub mean_interval: Option<f64>,
    /// True when intervals are present and all are within 10% of the mean.
    /// A regular interval strongly suggests a DRI segment in the header.
    pub is_regular: bool,
}

/// Scan `bytes[start..end]` for RST0–RST7 markers (FF D0 – FF D7).
///
/// Respects byte stuffing (FF 00 is not a marker) and fill bytes (FF FF …
/// before the actual marker byte).  Does NOT stop at EOI or unexpected
/// markers — this is a passive scan of already-extracted entropy data.
///
/// `start` and `end` are byte offsets into `bytes`; `end` is exclusive.
pub fn scan_restart_markers(bytes: &[u8], start: usize, end: usize) -> RestartScanSummary {
    let end = end.min(bytes.len());
    let mut markers: Vec<RestartMarkerInfo> = Vec::new();

    let mut i = start;
    while i < end {
        if bytes[i] != 0xFF {
            i += 1;
            continue;
        }

        // Record position of the leading 0xFF byte.
        let ff_pos = i;

        // Skip fill bytes (consecutive 0xFF).
        while i < end && bytes[i] == 0xFF {
            i += 1;
        }

        if i >= end {
            break;
        }

        let marker_byte = bytes[i];
        i += 1;

        if marker_byte == 0x00 {
            // Byte stuffing: FF 00 represents a literal 0xFF in entropy data.
            continue;
        }

        if (0xD0..=0xD7).contains(&marker_byte) {
            markers.push(RestartMarkerInfo {
                offset: ff_pos,
                marker: marker_byte,
            });
        }
        // Otherwise: skip and continue (EOI, other markers, etc.)
    }

    let count = markers.len() as u32;

    if count < 2 {
        return RestartScanSummary {
            count,
            markers,
            intervals: Vec::new(),
            mean_interval: None,
            is_regular: false,
        };
    }

    // Compute intervals between consecutive RST marker offsets.
    let intervals: Vec<usize> = markers
        .windows(2)
        .map(|w| w[1].offset - w[0].offset)
        .collect();

    let sum: usize = intervals.iter().sum();
    let mean = sum as f64 / intervals.len() as f64;

    // is_regular: all intervals within 10% of mean.
    let is_regular = intervals.iter().all(|&iv| {
        let diff = (iv as f64 - mean).abs();
        diff <= mean * 0.10
    });

    RestartScanSummary {
        count,
        markers,
        intervals,
        mean_interval: Some(mean),
        is_regular,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    /// Build a byte stuffing pair: FF 00.
    fn byte_stuff() -> Vec<u8> {
        vec![0xFF, 0x00]
    }

    /// Build a single RST marker with the given value (0xD0–0xD7).
    fn rst(n: u8) -> Vec<u8> {
        assert!((0xD0..=0xD7).contains(&n));
        vec![0xFF, n]
    }

    /// Build a run of `len` entropy bytes with no special sequences.
    fn entropy(len: usize) -> Vec<u8> {
        // Use 0x80 which is safe entropy data.
        vec![0x80u8; len]
    }

    // -----------------------------------------------------------------------
    // empty / trivial cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_input() {
        let s = scan_restart_markers(&[], 0, 0);
        assert_eq!(s.count, 0);
        assert!(s.markers.is_empty());
        assert!(s.intervals.is_empty());
        assert!(s.mean_interval.is_none());
        assert!(!s.is_regular);
    }

    #[test]
    fn no_rst_markers() {
        // Pure entropy data with no 0xFF bytes.
        let data: Vec<u8> = (0u8..=0x7Fu8).collect();
        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 0);
        assert!(s.markers.is_empty());
        assert!(s.intervals.is_empty());
        assert!(s.mean_interval.is_none());
        assert!(!s.is_regular);
    }

    // -----------------------------------------------------------------------
    // single marker
    // -----------------------------------------------------------------------

    #[test]
    fn single_rst_marker() {
        let mut data = entropy(10);
        data.extend(rst(0xD3)); // RST3 at offset 10
        data.extend(entropy(10));

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 1);
        assert_eq!(s.markers[0].offset, 10);
        assert_eq!(s.markers[0].marker, 0xD3);
        assert!(s.intervals.is_empty());
        assert!(s.mean_interval.is_none());
        assert!(!s.is_regular);
    }

    // -----------------------------------------------------------------------
    // multiple markers — regular intervals
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_rst_regular_intervals() {
        // Place RST markers every 100 bytes.
        let interval = 100usize;
        let mut data = Vec::new();
        let rst_count = 5;
        for i in 0..rst_count {
            if i > 0 {
                data.extend(entropy(interval - 2)); // subtract 2 for the RST bytes themselves
            } else {
                data.extend(entropy(interval));
            }
            data.extend(rst(0xD0 + i as u8));
        }

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, rst_count as u32);
        assert_eq!(s.intervals.len(), rst_count - 1);
        assert!(s.mean_interval.is_some());
        assert!(s.is_regular, "expected regular intervals, got {:?}", s.intervals);
    }

    #[test]
    fn two_rst_markers_exact_same_interval() {
        let mut data = entropy(200);
        data.extend(rst(0xD0)); // at 200
        data.extend(entropy(198)); // 198 + 2 = 200 bytes to next RST
        data.extend(rst(0xD1)); // at 400

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 2);
        assert_eq!(s.intervals.len(), 1);
        assert_eq!(s.intervals[0], 200);
        assert_eq!(s.mean_interval, Some(200.0));
        assert!(s.is_regular);
    }

    // -----------------------------------------------------------------------
    // multiple markers — irregular intervals
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_rst_irregular_intervals() {
        // First gap: 100 bytes, second gap: 500 bytes — very unequal.
        let mut data = entropy(100);
        data.extend(rst(0xD0)); // offset 100
        data.extend(entropy(98));
        data.extend(rst(0xD1)); // offset 200
        data.extend(entropy(498));
        data.extend(rst(0xD2)); // offset 700

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 3);
        assert!(!s.is_regular, "intervals {:?} should be irregular", s.intervals);
    }

    // -----------------------------------------------------------------------
    // byte stuffing must not be treated as RST
    // -----------------------------------------------------------------------

    #[test]
    fn byte_stuffing_not_counted_as_rst() {
        // FF 00 is byte stuffing, not a marker.
        let mut data = Vec::new();
        data.extend(byte_stuff()); // FF 00
        data.extend(byte_stuff()); // FF 00
        data.extend(entropy(10));

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 0);
    }

    #[test]
    fn byte_stuffing_interleaved_with_rst() {
        let mut data = Vec::new();
        data.extend(byte_stuff()); // FF 00 — not a marker
        data.extend(entropy(48));
        data.extend(rst(0xD0)); // offset = 2 + 48 = 50
        data.extend(byte_stuff()); // FF 00 — not a marker
        data.extend(entropy(48));
        data.extend(rst(0xD1)); // offset = 50 + 2 + 2 + 48 = 102

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 2);
        assert_eq!(s.markers[0].offset, 50);
        assert_eq!(s.markers[1].offset, 102);
    }

    // -----------------------------------------------------------------------
    // fill bytes (FF FF … before marker byte) handled correctly
    // -----------------------------------------------------------------------

    #[test]
    fn fill_bytes_before_rst_marker() {
        // FF FF FF D4 — fill bytes followed by RST4.
        // The offset recorded should be the position of the first 0xFF.
        let mut data = entropy(10);
        let ff_pos = data.len(); // 10
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xD4]);
        data.extend(entropy(10));

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 1);
        assert_eq!(s.markers[0].offset, ff_pos);
        assert_eq!(s.markers[0].marker, 0xD4);
    }

    #[test]
    fn fill_bytes_before_byte_stuffing() {
        // FF FF 00 — this should be treated as fill bytes followed by 0x00,
        // which is NOT a restart marker (0x00 means byte stuffing).
        let data = vec![0xFF, 0xFF, 0x00];
        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 0);
    }

    // -----------------------------------------------------------------------
    // RST8 and above must not be counted
    // -----------------------------------------------------------------------

    #[test]
    fn rst8_not_counted() {
        // 0xD8 = SOI, not a restart marker. Must not be counted.
        let mut data = entropy(10);
        data.extend_from_slice(&[0xFF, 0xD8]); // SOI, not RST
        data.extend(entropy(10));

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 0);
    }

    #[test]
    fn eoi_marker_not_counted() {
        // 0xD9 = EOI, not a restart marker.
        let mut data = entropy(10);
        data.extend_from_slice(&[0xFF, 0xD9]);
        data.extend(entropy(10));

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 0);
    }

    #[test]
    fn all_rst_values_d0_through_d7_counted() {
        let mut data = Vec::new();
        for v in 0xD0u8..=0xD7u8 {
            data.extend(entropy(10));
            data.extend(rst(v));
        }

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 8);
        for (i, info) in s.markers.iter().enumerate() {
            assert_eq!(info.marker, 0xD0 + i as u8);
        }
    }

    // -----------------------------------------------------------------------
    // start/end bounds respected
    // -----------------------------------------------------------------------

    #[test]
    fn start_bound_respected() {
        // RST at offset 5, but we start scanning from 10 — should not be seen.
        let mut data = entropy(5);
        data.extend(rst(0xD0)); // at offset 5
        data.extend(entropy(4));
        data.extend(rst(0xD1)); // at offset 11
        data.extend(entropy(5));

        let s = scan_restart_markers(&data, 10, data.len());
        assert_eq!(s.count, 1);
        assert_eq!(s.markers[0].marker, 0xD1);
    }

    #[test]
    fn end_bound_respected() {
        // RST at offset 10 but we only scan up to offset 9 — should not be seen.
        let mut data = entropy(10);
        data.extend(rst(0xD0)); // at offset 10
        data.extend(entropy(5));

        let s = scan_restart_markers(&data, 0, 10);
        assert_eq!(s.count, 0);
    }

    #[test]
    fn end_clamped_to_slice_length() {
        let data = entropy(5);
        // end > data.len() should clamp gracefully.
        let s = scan_restart_markers(&data, 0, 1000);
        assert_eq!(s.count, 0);
    }

    #[test]
    fn start_equals_end_produces_empty() {
        let data = entropy(10);
        let s = scan_restart_markers(&data, 5, 5);
        assert_eq!(s.count, 0);
    }

    // -----------------------------------------------------------------------
    // is_regular boundary — exactly 10% deviation
    // -----------------------------------------------------------------------

    #[test]
    fn is_regular_exactly_at_10_percent_boundary() {
        // mean = 100, one interval at 90 (exactly 10% below) and one at 110 (exactly 10% above).
        // diff = 10 = 100 * 0.10 exactly → should be regular (<=).
        let mut data = entropy(90);
        data.extend(rst(0xD0)); // offset 90
        data.extend(entropy(98)); // next offset = 90 + 2 + 98 = 190
        data.extend(rst(0xD1)); // offset 190, interval = 100
        data.extend(entropy(108)); // next offset = 190 + 2 + 108 = 300
        data.extend(rst(0xD2)); // offset 300, interval = 110

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 3);
        // mean = (100 + 110) / 2 = 105
        // 100: diff from 105 = 5, 5 <= 105*0.1 = 10.5 → ok
        // 110: diff from 105 = 5, 5 <= 10.5 → ok
        assert!(s.is_regular);
    }

    #[test]
    fn is_regular_false_when_one_interval_exceeds_10_percent() {
        // Two intervals: 100 and 200. mean = 150.
        // 100: diff = 50, 50 > 15 → not regular.
        let mut data = entropy(100);
        data.extend(rst(0xD0)); // offset 100
        data.extend(entropy(98));
        data.extend(rst(0xD1)); // offset 200, interval 100
        data.extend(entropy(198));
        data.extend(rst(0xD2)); // offset 400, interval 200

        let s = scan_restart_markers(&data, 0, data.len());
        assert_eq!(s.count, 3);
        assert!(!s.is_regular);
    }
}
