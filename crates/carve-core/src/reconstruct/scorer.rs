use crate::jpeg::parse::parse_until_sos;

/// Quality score for a reconstructed JPEG candidate.
///
/// Computed entirely from the raw bytes of the entropy-coded stream — no JPEG
/// decoder is required.  The `total` field is the single value to use for
/// ranking; all other fields are diagnostics.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JpegScore {
    /// Shannon entropy of the entropy-coded stream, normalised to 0.0–1.0.
    ///
    /// 8 bits/byte → 1.0.  Real photos typically score ≥ 0.9 here.  Low values
    /// (< 0.7) suggest large repeated-byte runs characteristic of block-shift
    /// corruption or zero-padding.
    pub byte_entropy: f32,

    /// Proportion of distinct byte values (0–255) present in the stream.
    ///
    /// 1.0 means all 256 byte values appear; 0.0 means only one byte value.
    /// A healthy entropy stream usually visits > 200 of the 256 values, so
    /// values ≥ 0.8 are expected.
    pub unique_byte_ratio: f32,

    /// Count of unexpected JPEG markers found in the entropy stream.
    ///
    /// Byte-stuffed FF 00, fill bytes FF FF, and restart markers FF D0–FF D7
    /// are all valid and not counted.  Any other FF XX is unexpected and
    /// indicates the stream contains structural markers that a decoder would
    /// treat as the end of scan data.  Ideally 0.
    pub unexpected_markers: usize,

    /// Combined quality score 0.0–1.0 (higher = more likely a good recovery).
    pub total: f32,
}

/// Score a raw entropy-coded stream slice.
///
/// `data` must be the bytes immediately following the SOS segment payload —
/// i.e. what [`crate::jpeg::parse::PreSosResult::scan_start`] points at,
/// with any trailing EOI (`FF D9`) already stripped.
pub fn score_entropy_stream(data: &[u8]) -> JpegScore {
    let byte_entropy = compute_byte_entropy(data);
    let unique_byte_ratio = compute_unique_byte_ratio(data);
    let unexpected_markers = count_unexpected_markers(data);

    // Penalty scales with unexpected marker count but is capped at 0.3.
    let penalty = (unexpected_markers as f32 * 0.1).min(0.3);
    let total = (0.6 * byte_entropy + 0.4 * unique_byte_ratio - penalty).clamp(0.0, 1.0);

    JpegScore { byte_entropy, unique_byte_ratio, unexpected_markers, total }
}

/// Score a complete rebuilt JPEG from its raw bytes.
///
/// Re-parses the pre-SOS header to locate the entropy stream start, strips any
/// trailing EOI (`FF D9`), then delegates to [`score_entropy_stream`].
/// Returns `None` if the bytes cannot be parsed as a valid JPEG.
pub fn score_rebuilt_jpeg(jpeg_bytes: &[u8]) -> Option<JpegScore> {
    let pre_sos = parse_until_sos(jpeg_bytes, 0, jpeg_bytes.len()).ok()?;
    let entropy = &jpeg_bytes[pre_sos.scan_start..];
    let entropy = entropy.strip_suffix(&[0xFF, 0xD9]).unwrap_or(entropy);
    Some(score_entropy_stream(entropy))
}

/// Shannon entropy of `data`, normalised to 0.0–1.0 (8 bits/byte = 1.0).
fn compute_byte_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f32;
    let h: f32 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / n;
            -p * p.log2()
        })
        .sum();
    (h / 8.0).clamp(0.0, 1.0)
}

/// Fraction of the 256 possible byte values that appear in `data`.
fn compute_unique_byte_ratio(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    seen.iter().filter(|&&s| s).count() as f32 / 256.0
}

/// Count unexpected markers (FF XX) in the entropy stream.
///
/// Valid sequences skipped without counting:
/// - FF 00  (byte stuffing)
/// - FF FF  (fill byte — skip by one)
/// - FF D0–FF D7  (restart markers)
fn count_unexpected_markers(data: &[u8]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        if data[i] == 0xFF {
            match data[i + 1] {
                0x00 => i += 2,       // byte stuffing — valid
                0xFF => i += 1,       // fill byte — skip one
                0xD0..=0xD7 => i += 2, // RST0–RST7 — valid
                _ => { count += 1; i += 2; }
            }
        } else {
            i += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uniform_data(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    fn all_bytes_data() -> Vec<u8> {
        (0u8..=255).collect()
    }

    // ---- byte entropy ----

    #[test]
    fn entropy_of_uniform_data_is_zero() {
        let score = score_entropy_stream(&uniform_data(0xAB, 1000));
        assert!(score.byte_entropy < 0.01, "uniform bytes → zero entropy");
    }

    #[test]
    fn entropy_of_all_256_values_is_near_one() {
        // With exactly one occurrence of each byte the Shannon entropy is 8 bits/byte.
        let score = score_entropy_stream(&all_bytes_data());
        assert!(score.byte_entropy > 0.99, "all-256-values entropy ≈ 1.0, got {}", score.byte_entropy);
    }

    #[test]
    fn entropy_of_empty_stream_is_zero() {
        let score = score_entropy_stream(&[]);
        assert_eq!(score.byte_entropy, 0.0);
        assert_eq!(score.unique_byte_ratio, 0.0);
        assert_eq!(score.unexpected_markers, 0);
    }

    #[test]
    fn high_entropy_data_scores_higher_than_low_entropy() {
        let high = score_entropy_stream(&all_bytes_data());
        let low  = score_entropy_stream(&uniform_data(0x00, 256));
        assert!(high.total > low.total, "high entropy should outscore low entropy");
    }

    // ---- unique byte ratio ----

    #[test]
    fn unique_byte_ratio_single_value_is_near_zero() {
        let score = score_entropy_stream(&uniform_data(0x42, 512));
        assert!(score.unique_byte_ratio < 0.01);
    }

    #[test]
    fn unique_byte_ratio_all_values_is_one() {
        let score = score_entropy_stream(&all_bytes_data());
        assert!((score.unique_byte_ratio - 1.0).abs() < f32::EPSILON);
    }

    // ---- unexpected markers ----

    #[test]
    fn byte_stuffing_not_counted_as_unexpected() {
        let data = vec![0xAB, 0xFF, 0x00, 0xCD]; // FF 00 is byte stuffing
        let score = score_entropy_stream(&data);
        assert_eq!(score.unexpected_markers, 0);
    }

    #[test]
    fn rst_markers_not_counted_as_unexpected() {
        let data = vec![0xAB, 0xFF, 0xD3, 0xCD]; // FF D3 is RST3
        let score = score_entropy_stream(&data);
        assert_eq!(score.unexpected_markers, 0);
    }

    #[test]
    fn fill_bytes_not_counted_as_unexpected() {
        let data = vec![0xFF, 0xFF, 0x00]; // fill byte then stuffed FF
        let score = score_entropy_stream(&data);
        assert_eq!(score.unexpected_markers, 0);
    }

    #[test]
    fn sof_marker_in_stream_is_unexpected() {
        let data = vec![0xAB, 0xFF, 0xC0, 0xCD]; // FF C0 = SOF0 — unexpected in entropy
        let score = score_entropy_stream(&data);
        assert_eq!(score.unexpected_markers, 1);
    }

    #[test]
    fn multiple_unexpected_markers_counted() {
        // FF C0, FF C4, FF DA = SOF0, DHT, SOS — all unexpected
        let data = vec![0xFF, 0xC0, 0xFF, 0xC4, 0xFF, 0xDA];
        let score = score_entropy_stream(&data);
        assert_eq!(score.unexpected_markers, 3);
    }

    #[test]
    fn unexpected_markers_reduce_total_score() {
        let clean = score_entropy_stream(&all_bytes_data());
        // Insert unexpected markers by replacing some bytes with FF XX
        let mut dirty = all_bytes_data();
        dirty[0] = 0xFF; dirty[1] = 0xC0;
        dirty[2] = 0xFF; dirty[3] = 0xC0;
        dirty[4] = 0xFF; dirty[5] = 0xC0;
        let dirty_score = score_entropy_stream(&dirty);
        assert!(dirty_score.total <= clean.total);
    }

    // ---- total score ----

    #[test]
    fn total_score_is_clamped_to_0_1() {
        for data in [uniform_data(0, 256), all_bytes_data()] {
            let score = score_entropy_stream(&data);
            assert!((0.0..=1.0).contains(&score.total));
        }
    }

    // ---- score_rebuilt_jpeg ----

    fn make_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        let mut v = vec![0xFF, marker, (len >> 8) as u8, len as u8];
        v.extend_from_slice(payload);
        v
    }

    fn make_rebuilt_jpeg(entropy: &[u8]) -> Vec<u8> {
        use crate::jpeg::markers;
        let mut buf = vec![0xFF, markers::SOI];
        let mut dqt = vec![0x00u8];
        dqt.extend_from_slice(&[16u8; 64]);
        buf.extend(make_segment(markers::DQT, &dqt));
        let sof = [0x08, 0x00, 0xF0, 0x01, 0x40, 0x03,
                   0x01, 0x21, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01];
        buf.extend(make_segment(markers::SOF0, &sof));
        let sos = [0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00];
        buf.extend(make_segment(markers::SOS, &sos));
        buf.extend_from_slice(entropy);
        buf.extend_from_slice(&[0xFF, 0xD9]);
        buf
    }

    #[test]
    fn score_rebuilt_jpeg_returns_some_for_valid_jpeg() {
        let jpeg = make_rebuilt_jpeg(&all_bytes_data());
        assert!(score_rebuilt_jpeg(&jpeg).is_some());
    }

    #[test]
    fn score_rebuilt_jpeg_returns_none_for_garbage() {
        assert!(score_rebuilt_jpeg(&[0x00u8; 64]).is_none());
    }

    #[test]
    fn score_rebuilt_jpeg_strips_eoi_before_scoring() {
        // A JPEG with high-entropy data should score the same regardless of EOI presence.
        let entropy: Vec<u8> = all_bytes_data();
        let jpeg = make_rebuilt_jpeg(&entropy);
        let score = score_rebuilt_jpeg(&jpeg).unwrap();

        // Compare against scoring the entropy bytes directly (without EOI).
        let direct = score_entropy_stream(&entropy);
        assert!((score.total - direct.total).abs() < 0.01,
            "score_rebuilt_jpeg should strip EOI before scoring");
    }
}
