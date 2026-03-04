// Entropy stream scanning

#[derive(Debug, PartialEq)]
pub enum EntropyTermination {
    /// Found FF D9 (EOI); `eoi_pos` points to the 0xFF byte.
    Eoi { eoi_pos: usize },
    /// Hit FF <marker> where marker is not stuffing, restart, or EOI.
    InvalidMarker { marker: u8, at: usize },
    /// Reached `max_end` (or end of slice) without finding EOI.
    Truncated,
}

#[derive(Debug)]
pub struct EntropyResult {
    pub termination: EntropyTermination,
    /// Number of bytes consumed from `start` before termination.
    pub bytes_scanned: usize,
    /// Number of RST0..RST7 markers seen.
    pub restart_markers_seen: u32,
}

/// Scan the JPEG entropy-coded data stream.
///
/// - `start`   : first byte after the SOS segment payload.
/// - `max_end` : exclusive upper bound (e.g. `bytes.len()` or a candidate limit).
///
/// Rules (per JPEG spec §B.1.1.5):
///   - FF 00         → byte stuffing; the 0xFF is data, not a marker.
///   - FF D0..D7     → RST marker; allowed inside entropy data.
///   - FF D9         → EOI; terminates the entropy stream.
///   - FF <anything else> → invalid; terminates with `InvalidMarker`.
///   - FF FF …       → fill bytes before the actual marker byte.
pub fn scan_entropy_stream(bytes: &[u8], start: usize, max_end: usize) -> EntropyResult {
    let limit = max_end.min(bytes.len());
    let mut pos = start;
    let mut restart_markers_seen = 0u32;

    while pos < limit {
        if bytes[pos] != 0xFF {
            pos += 1;
            continue;
        }

        // Found 0xFF. Skip any fill bytes (0xFF 0xFF …) to reach the marker byte.
        let mut next = pos + 1;
        while next < limit && bytes[next] == 0xFF {
            next += 1;
        }

        if next >= limit {
            // Truncated: slice ends inside an FF … sequence.
            return EntropyResult {
                termination: EntropyTermination::Truncated,
                bytes_scanned: pos.saturating_sub(start),
                restart_markers_seen,
            };
        }

        let marker = bytes[next];

        match marker {
            0x00 => {
                // Byte stuffing: FF 00 represents a literal 0xFF value in the bitstream.
                pos = next + 1;
            }
            0xD0..=0xD7 => {
                // Restart marker RST0..RST7 — valid inside entropy data.
                restart_markers_seen += 1;
                pos = next + 1;
            }
            0xD9 => {
                // EOI — normal end of image.
                return EntropyResult {
                    termination: EntropyTermination::Eoi { eoi_pos: pos },
                    bytes_scanned: pos.saturating_sub(start),
                    restart_markers_seen,
                };
            }
            _ => {
                // Any other marker is invalid inside entropy data.
                return EntropyResult {
                    termination: EntropyTermination::InvalidMarker { marker, at: pos },
                    bytes_scanned: pos.saturating_sub(start),
                    restart_markers_seen,
                };
            }
        }
    }

    EntropyResult {
        termination: EntropyTermination::Truncated,
        bytes_scanned: limit.saturating_sub(start),
        restart_markers_seen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // helpers

    fn eoi_at(pos: usize) -> EntropyTermination {
        EntropyTermination::Eoi { eoi_pos: pos }
    }

    fn invalid_at(marker: u8, at: usize) -> EntropyTermination {
        EntropyTermination::InvalidMarker { marker, at }
    }

    // basic termination

    #[test]
    fn empty_range_is_truncated() {
        let data = [0x00u8; 0];
        let r = scan_entropy_stream(&data, 0, 0);
        assert_eq!(r.termination, EntropyTermination::Truncated);
        assert_eq!(r.bytes_scanned, 0);
        assert_eq!(r.restart_markers_seen, 0);
    }

    #[test]
    fn start_equals_max_end_is_truncated() {
        let data = [0xAB, 0xCD, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 2, 2); // zero-length window
        assert_eq!(r.termination, EntropyTermination::Truncated);
        assert_eq!(r.bytes_scanned, 0);
    }

    #[test]
    fn no_markers_scans_to_end_truncated() {
        let data = [0x10u8, 0x20, 0x30, 0x40];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, EntropyTermination::Truncated);
        assert_eq!(r.bytes_scanned, 4);
    }

    // EOI detection 

    #[test]
    fn eoi_at_start() {
        let data = [0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, eoi_at(0));
        assert_eq!(r.bytes_scanned, 0);
    }

    #[test]
    fn eoi_after_payload() {
        let data = [0x10, 0x20, 0x30, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, eoi_at(3));
        assert_eq!(r.bytes_scanned, 3);
    }

    #[test]
    fn eoi_respects_max_end() {
        // EOI exists at byte 3, but max_end cuts off before it.
        let data = [0x10, 0x20, 0x30, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 0, 3);
        assert_eq!(r.termination, EntropyTermination::Truncated);
        assert_eq!(r.bytes_scanned, 3);
    }

    // byte stuffing

    #[test]
    fn stuffed_ff_not_treated_as_eoi() {
        // FF 00 = stuffed 0xFF; should not terminate the scan.
        let data = [0xFF, 0x00, 0x10, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, eoi_at(3));
        assert_eq!(r.bytes_scanned, 3);
    }

    #[test]
    fn multiple_stuffed_bytes() {
        let data = [0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, eoi_at(6));
        assert_eq!(r.restart_markers_seen, 0);
    }

    // restart markers 

    #[test]
    fn rst0_is_allowed() {
        let data = [0x10, 0xFF, 0xD0, 0x20, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, eoi_at(4));
        assert_eq!(r.restart_markers_seen, 1);
    }

    #[test]
    fn rst7_is_allowed() {
        let data = [0xFF, 0xD7, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, eoi_at(2));
        assert_eq!(r.restart_markers_seen, 1);
    }

    #[test]
    fn all_restart_markers_counted() {
        // RST0 through RST7 (8 markers)
        let mut data: Vec<u8> = Vec::new();
        for rst in 0xD0u8..=0xD7 {
            data.push(0xFF);
            data.push(rst);
        }
        data.push(0xFF);
        data.push(0xD9); // EOI

        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.restart_markers_seen, 8);
        assert_eq!(r.termination, eoi_at(data.len() - 2));
    }

    // invalid markers

    #[test]
    fn sof0_marker_in_entropy_is_invalid() {
        let data = [0x10, 0x20, 0xFF, 0xC0, 0x00, 0x11];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, invalid_at(0xC0, 2));
    }

    #[test]
    fn app0_marker_in_entropy_is_invalid() {
        let data = [0xFF, 0xE0];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, invalid_at(0xE0, 0));
    }

    #[test]
    fn sos_marker_in_entropy_is_invalid() {
        let data = [0x10, 0xFF, 0xDA, 0x00];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, invalid_at(0xDA, 1));
    }

    // fill bytes (FF FF … <marker>)

    #[test]
    fn fill_bytes_before_eoi() {
        // FF FF FF D9 — two fill bytes then EOI
        let data = [0xFF, 0xFF, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, eoi_at(0));
    }

    #[test]
    fn fill_bytes_before_restart() {
        let data = [0xFF, 0xFF, 0xD3, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.restart_markers_seen, 1);
        assert_eq!(r.termination, eoi_at(3));
    }

    #[test]
    fn fill_bytes_before_invalid_marker() {
        let data = [0xFF, 0xFF, 0xC0];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, invalid_at(0xC0, 0));
    }

    // truncated mid-marker 

    #[test]
    fn truncated_after_ff_byte() {
        // Slice ends right after 0xFF with no following byte
        let data = [0x10, 0x20, 0xFF];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, EntropyTermination::Truncated);
    }

    #[test]
    fn truncated_after_fill_bytes() {
        // FF FF FF with no marker byte following
        let data = [0x10, 0xFF, 0xFF, 0xFF];
        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, EntropyTermination::Truncated);
    }

    // start offset

    #[test]
    fn nonzero_start_offset() {
        // Ignore garbage before `start`
        let data = [0x00, 0x00, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 2, data.len());
        assert_eq!(r.termination, eoi_at(2));
        assert_eq!(r.bytes_scanned, 0);
    }

    #[test]
    fn nonzero_start_counts_bytes_from_start() {
        let data = [0x00, 0x00, 0x10, 0x20, 0xFF, 0xD9];
        let r = scan_entropy_stream(&data, 2, data.len());
        assert_eq!(r.termination, eoi_at(4));
        assert_eq!(r.bytes_scanned, 2); // scanned bytes[2..4]
    }

    // realistic entropy stream

    #[test]
    fn realistic_entropy_with_restarts_and_stuffing() {
        // Simulate: payload, FF 00 stuffing, RST3, more payload, EOI
        let mut data: Vec<u8> = vec![0xAB, 0xCD, 0xEF];
        data.extend_from_slice(&[0xFF, 0x00]); // stuffed 0xFF
        data.extend_from_slice(&[0x12, 0x34]);
        data.extend_from_slice(&[0xFF, 0xD3]); // RST3
        data.extend_from_slice(&[0x56, 0x78]);
        let eoi_pos = data.len();
        data.extend_from_slice(&[0xFF, 0xD9]); // EOI

        let r = scan_entropy_stream(&data, 0, data.len());
        assert_eq!(r.termination, eoi_at(eoi_pos));
        assert_eq!(r.restart_markers_seen, 1);
        assert_eq!(r.bytes_scanned, eoi_pos);
    }
}
