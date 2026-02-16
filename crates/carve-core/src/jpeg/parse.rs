// Pre-SOS segment parsing
use super::markers;

#[inline]
pub fn be_u16(bytes: &[u8], i: usize) -> Option<u16> {
    let hi = *bytes.get(i)? as u16;
    let lo = *bytes.get(i + 1)? as u16;
    Some((hi << 8) | lo)
}

#[derive(Debug)]
pub struct ParsedSegment {
    pub marker: u8,
    pub marker_pos: usize,   // points at the 0xFF byte
    pub payload_pos: usize,  // start of payload (after len bytes)
    pub payload_len: usize,
    pub seg_end: usize,      // exclusive end of segment
}

#[derive(Debug, Clone)]
pub struct PreSosResult {
    pub sos_marker_pos: usize,
    pub scan_start: usize, // first byte after SOS segment payload
    pub segments_parsed: usize,

    // lightweight metadata/flags you’ll use for confidence + reporting
    pub has_exif: bool,
    pub has_dqt: bool,
    pub has_dht: bool,
    pub width: Option<u16>,
    pub height: Option<u16>,
    pub is_progressive: Option<bool>,
}

#[derive(Debug, Clone)]
pub enum ParseError {
    OutOfBounds,
    NotJpeg,
    MissingSos,
    InvalidMarkerStream { at: usize },
    InvalidSegmentLength { at: usize, len: u16 },
    SegmentLengthOverflows { at: usize, len: u16 },
    BadSofPayload { at: usize },
}

/// Reads the next marker starting at or after `pos`.
/// Returns (marker_byte, marker_pos, next_pos_after_marker_byte).
///
/// marker_pos points to the 0xFF prefix byte.
/// next_pos is the index immediately after the marker byte (where len starts, if any).
pub fn read_marker(bytes: &[u8], mut pos: usize, limit: usize) -> Result<(u8, usize, usize), ParseError> {
    // Find 0xFF
    while pos < limit && bytes[pos] != 0xFF {
        pos += 1;
    }
    if pos >= limit {
        return Err(ParseError::OutOfBounds);
    }

    let marker_pos = pos;

    // Skip fill bytes 0xFF 0xFF 0xFF...
    while pos < limit && bytes[pos] == 0xFF {
        pos += 1;
    }
    if pos >= limit {
        return Err(ParseError::OutOfBounds);
    }

    let marker = bytes[pos];
    let next_pos = pos + 1; // points after marker byte
    Ok((marker, marker_pos, next_pos))
}

pub fn parse_segment(bytes: &[u8], marker: u8, marker_pos: usize, pos_after_marker: usize, limit: usize)
    -> Result<ParsedSegment, ParseError>
{
    if !markers::has_length(marker) {
        return Err(ParseError::InvalidMarkerStream { at: marker_pos });
    }

    // length field is 2 bytes at pos_after_marker
    let len_u16 = be_u16(bytes, pos_after_marker).ok_or(ParseError::OutOfBounds)?;
    if len_u16 < 2 {
        return Err(ParseError::InvalidSegmentLength { at: marker_pos, len: len_u16 });
    }
    let len = len_u16 as usize;

    let payload_pos = pos_after_marker + 2;
    let payload_len = len - 2;
    let seg_end = payload_pos.checked_add(payload_len).ok_or(ParseError::OutOfBounds)?;

    if seg_end > limit {
        return Err(ParseError::SegmentLengthOverflows { at: marker_pos, len: len_u16 });
    }

    Ok(ParsedSegment {
        marker,
        marker_pos,
        payload_pos,
        payload_len,
        seg_end,
    })
}

fn parse_sof(bytes: &[u8], seg: &ParsedSegment) -> Result<(u16, u16), ParseError> {
    // Need at least 6 bytes: P(1) + Y(2) + X(2) + Nf(1)
    if seg.payload_len < 6 {
        return Err(ParseError::BadSofPayload { at: seg.marker_pos });
    }
    let p = seg.payload_pos;

    let height = be_u16(bytes, p + 1).ok_or(ParseError::OutOfBounds)?;
    let width  = be_u16(bytes, p + 3).ok_or(ParseError::OutOfBounds)?;

    // Basic sanity (don’t be too strict)
    if width == 0 || height == 0 {
        return Err(ParseError::BadSofPayload { at: seg.marker_pos });
    }
    Ok((width, height))
}

fn seg_has_exif(bytes: &[u8], seg: &ParsedSegment) -> bool {
    // APP1 payload often starts with "Exif\0\0"
    if seg.marker != 0xE1 || seg.payload_len < 6 {
        return false;
    }
    let p = seg.payload_pos;
    bytes.get(p..p+6) == Some(b"Exif\0\0")
}

pub fn parse_until_sos(bytes: &[u8], start: usize, max_size_bytes: usize) -> Result<PreSosResult, ParseError> {
    // Candidate limit to avoid scanning forever in disk images
    let limit = bytes.len().min(start.saturating_add(max_size_bytes));

    // Validate SOI
    if start + 2 > limit {
        return Err(ParseError::OutOfBounds);
    }
    if bytes[start] != 0xFF || bytes[start + 1] != markers::SOI {
        return Err(ParseError::NotJpeg);
    }

    let mut pos = start + 2;
    let mut segments_parsed = 0usize;

    let mut has_exif = false;
    let mut has_dqt = false;
    let mut has_dht = false;
    let mut width: Option<u16> = None;
    let mut height: Option<u16> = None;
    let mut is_progressive: Option<bool> = None;

    // Loop markers until SOS
    while pos < limit {
        let (marker, marker_pos, next_pos) = read_marker(bytes, pos, limit)?;

        // Pre-SOS should not normally contain restart markers; treat as corruption
        if markers::is_restart(marker) {
            return Err(ParseError::InvalidMarkerStream { at: marker_pos });
        }

        // SOI inside header stream is suspicious (nested); reject to reduce false positives
        if marker == markers::SOI {
            return Err(ParseError::InvalidMarkerStream { at: marker_pos });
        }

        // If we hit SOS, parse its segment and stop.
        if marker == markers::SOS {
            let seg = parse_segment(bytes, marker, marker_pos, next_pos, limit)?;
            segments_parsed += 1;

            return Ok(PreSosResult {
                sos_marker_pos: marker_pos,
                scan_start: seg.seg_end, // entropy starts right after SOS segment
                segments_parsed,
                has_exif,
                has_dqt,
                has_dht,
                width,
                height,
                is_progressive,
            });
        }

        // EOI before SOS is abnormal; treat as invalid candidate.
        if marker == markers::EOI {
            return Err(ParseError::InvalidMarkerStream { at: marker_pos });
        }

        // For all other markers, we expect a length-bearing segment
        if !markers::has_length(marker) {
            // TEM (0x01) is weird in headers; treat as invalid
            return Err(ParseError::InvalidMarkerStream { at: marker_pos });
        }

        let seg = parse_segment(bytes, marker, marker_pos, next_pos, limit)?;
        segments_parsed += 1;

        // Track flags / metadata
        if seg_has_exif(bytes, &seg) { has_exif = true; }
        if seg.marker == markers::DQT { has_dqt = true; }
        if seg.marker == markers::DHT { has_dht = true; }

        if seg.marker == markers::SOF0 || seg.marker == markers::SOF2 {
            let (w, h) = parse_sof(bytes, &seg)?;
            width = Some(w);
            height = Some(h);
            is_progressive = Some(seg.marker == markers::SOF2);
        }

        // Move to next segment
        pos = seg.seg_end;
    }

    Err(ParseError::MissingSos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::markers;

    // helpers

    /// Build a minimal length-bearing segment: FF <marker> <len_hi> <len_lo> <payload...>
    fn make_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        let mut v = vec![0xFF, marker, (len >> 8) as u8, len as u8];
        v.extend_from_slice(payload);
        v
    }

    /// Build a minimal valid JPEG header: SOI + DQT + SOS (with tiny payloads)
    fn make_minimal_jpeg() -> Vec<u8> {
        let mut buf = vec![0xFF, markers::SOI];          // SOI
        buf.extend(make_segment(markers::DQT, &[0; 4])); // DQT with 4-byte payload
        buf.extend(make_segment(markers::SOS, &[0; 4])); // SOS with 4-byte payload
        buf
    }

    // be_u16

    #[test]
    fn be_u16_valid() {
        assert_eq!(be_u16(&[0x00, 0x02], 0), Some(2));
        assert_eq!(be_u16(&[0x01, 0x00], 0), Some(256));
        assert_eq!(be_u16(&[0xFF, 0xFF], 0), Some(0xFFFF));
    }

    #[test]
    fn be_u16_out_of_bounds() {
        assert_eq!(be_u16(&[0x01], 0), None);
        assert_eq!(be_u16(&[], 0), None);
        assert_eq!(be_u16(&[0x00, 0x01], 1), None);
    }

    // read_marker

    #[test]
    fn read_marker_basic() {
        let data = [0xFF, 0xE0]; // APP0
        let (marker, mpos, next) = read_marker(&data, 0, data.len()).unwrap();
        assert_eq!(marker, 0xE0);
        assert_eq!(mpos, 0);
        assert_eq!(next, 2);
    }

    #[test]
    fn read_marker_skips_fill_bytes() {
        let data = [0xFF, 0xFF, 0xFF, 0xE0]; // three FF fill, then APP0
        let (marker, mpos, next) = read_marker(&data, 0, data.len()).unwrap();
        assert_eq!(marker, 0xE0);
        assert_eq!(mpos, 0);
        assert_eq!(next, 4);
    }

    #[test]
    fn read_marker_empty_input() {
        assert!(read_marker(&[], 0, 0).is_err());
    }

    #[test]
    fn read_marker_only_ff() {
        let data = [0xFF];
        assert!(read_marker(&data, 0, data.len()).is_err());
    }

    // parse_segment

    #[test]
    fn parse_segment_valid_app0() {
        // FF E0 00 05 XX XX XX  (len=5 → 3 bytes payload)
        let data = [0xFF, 0xE0, 0x00, 0x05, 0xAA, 0xBB, 0xCC];
        let seg = parse_segment(&data, 0xE0, 0, 2, data.len()).unwrap();
        assert_eq!(seg.marker, 0xE0);
        assert_eq!(seg.marker_pos, 0);
        assert_eq!(seg.payload_pos, 4);
        assert_eq!(seg.payload_len, 3);
        assert_eq!(seg.seg_end, 7);
    }

    #[test]
    fn parse_segment_length_too_small() {
        // len = 1, which is < 2 (invalid)
        let data = [0xFF, 0xE0, 0x00, 0x01];
        let err = parse_segment(&data, 0xE0, 0, 2, data.len()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidSegmentLength { at: 0, len: 1 }));
    }

    #[test]
    fn parse_segment_length_zero() {
        let data = [0xFF, 0xE0, 0x00, 0x00];
        let err = parse_segment(&data, 0xE0, 0, 2, data.len()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidSegmentLength { at: 0, len: 0 }));
    }

    #[test]
    fn parse_segment_length_overflows_file() {
        // len = 0x00FF = 255, but file is only 6 bytes
        let data = [0xFF, 0xE0, 0x00, 0xFF, 0x00, 0x00];
        let err = parse_segment(&data, 0xE0, 0, 2, data.len()).unwrap_err();
        assert!(matches!(err, ParseError::SegmentLengthOverflows { .. }));
    }

    #[test]
    fn parse_segment_minimum_valid_length() {
        // len = 2 → 0 bytes payload, still valid
        let data = [0xFF, 0xE0, 0x00, 0x02];
        let seg = parse_segment(&data, 0xE0, 0, 2, data.len()).unwrap();
        assert_eq!(seg.payload_len, 0);
        assert_eq!(seg.seg_end, 4);
    }

    #[test]
    fn parse_segment_rejects_no_length_marker() {
        // SOI has no length field
        let data = [0xFF, markers::SOI, 0x00, 0x02];
        let err = parse_segment(&data, markers::SOI, 0, 2, data.len()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMarkerStream { .. }));
    }

    #[test]
    fn parse_segment_unknown_marker_with_valid_length() {
        // 0xFE = COM, a less common but valid length-bearing marker
        let data = [0xFF, 0xFE, 0x00, 0x04, 0x41, 0x42];
        let seg = parse_segment(&data, 0xFE, 0, 2, data.len()).unwrap();
        assert_eq!(seg.marker, 0xFE);
        assert_eq!(seg.payload_len, 2);
    }

    // parse_until_sos 

    #[test]
    fn parse_until_sos_minimal() {
        let jpeg = make_minimal_jpeg();
        let result = parse_until_sos(&jpeg, 0, jpeg.len()).unwrap();
        assert!(result.has_dqt);
        assert!(!result.has_exif);
        assert!(!result.has_dht);
        assert_eq!(result.segments_parsed, 2); // DQT + SOS
    }

    #[test]
    fn parse_until_sos_not_jpeg() {
        let data = [0x00, 0x00, 0x00, 0x00];
        let err = parse_until_sos(&data, 0, data.len()).unwrap_err();
        assert!(matches!(err, ParseError::NotJpeg));
    }

    #[test]
    fn parse_until_sos_empty() {
        assert!(parse_until_sos(&[], 0, 0).is_err());
    }

    #[test]
    fn parse_until_sos_missing_sos() {
        // SOI + DQT but no SOS
        let mut buf = vec![0xFF, markers::SOI];
        buf.extend(make_segment(markers::DQT, &[0; 4]));
        let err = parse_until_sos(&buf, 0, buf.len()).unwrap_err();
        assert!(matches!(err, ParseError::MissingSos));
    }

    #[test]
    fn parse_until_sos_rejects_restart_in_header() {
        // SOI + RST0 is invalid before SOS
        let buf = vec![0xFF, markers::SOI, 0xFF, 0xD0];
        let err = parse_until_sos(&buf, 0, buf.len()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMarkerStream { .. }));
    }

    #[test]
    fn parse_until_sos_rejects_eoi_before_sos() {
        let buf = vec![0xFF, markers::SOI, 0xFF, markers::EOI];
        let err = parse_until_sos(&buf, 0, buf.len()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMarkerStream { .. }));
    }

    #[test]
    fn parse_until_sos_rejects_nested_soi() {
        // SOI then another SOI is suspicious
        let buf = vec![0xFF, markers::SOI, 0xFF, markers::SOI];
        let err = parse_until_sos(&buf, 0, buf.len()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMarkerStream { .. }));
    }

    #[test]
    fn parse_until_sos_with_sof0_extracts_dimensions() {
        let mut buf = vec![0xFF, markers::SOI];

        // SOF0 payload: precision(1) + height(2) + width(2) + components(1) = 6 bytes min
        // height=480 (0x01E0), width=640 (0x0280)
        let sof_payload = [0x08, 0x01, 0xE0, 0x02, 0x80, 0x03];
        buf.extend(make_segment(markers::SOF0, &sof_payload));
        buf.extend(make_segment(markers::SOS, &[0; 4]));

        let result = parse_until_sos(&buf, 0, buf.len()).unwrap();
        assert_eq!(result.width, Some(640));
        assert_eq!(result.height, Some(480));
        assert_eq!(result.is_progressive, Some(false));
    }

    #[test]
    fn parse_until_sos_sof2_detected_as_progressive() {
        let mut buf = vec![0xFF, markers::SOI];
        let sof_payload = [0x08, 0x00, 0x64, 0x00, 0xC8, 0x03]; // 100x200
        buf.extend(make_segment(markers::SOF2, &sof_payload));
        buf.extend(make_segment(markers::SOS, &[0; 4]));

        let result = parse_until_sos(&buf, 0, buf.len()).unwrap();
        assert_eq!(result.is_progressive, Some(true));
        assert_eq!(result.width, Some(200));
        assert_eq!(result.height, Some(100));
    }

    #[test]
    fn parse_until_sos_detects_exif() {
        let mut buf = vec![0xFF, markers::SOI];

        // APP1 with Exif header
        let mut exif_payload = b"Exif\0\0".to_vec();
        exif_payload.extend_from_slice(&[0; 10]); // dummy TIFF data
        buf.extend(make_segment(0xE1, &exif_payload));
        buf.extend(make_segment(markers::SOS, &[0; 4]));

        let result = parse_until_sos(&buf, 0, buf.len()).unwrap();
        assert!(result.has_exif);
    }

    #[test]
    fn parse_until_sos_detects_dht() {
        let mut buf = vec![0xFF, markers::SOI];
        buf.extend(make_segment(markers::DHT, &[0; 4]));
        buf.extend(make_segment(markers::SOS, &[0; 4]));

        let result = parse_until_sos(&buf, 0, buf.len()).unwrap();
        assert!(result.has_dht);
    }

    #[test]
    fn parse_until_sos_nonzero_start_offset() {
        // Garbage bytes before the JPEG
        let mut buf = vec![0x00, 0x00, 0x00];
        let start = buf.len();
        buf.push(0xFF);
        buf.push(markers::SOI);
        buf.extend(make_segment(markers::SOS, &[0; 4]));

        let result = parse_until_sos(&buf, start, buf.len()).unwrap();
        assert_eq!(result.segments_parsed, 1); // just SOS
    }

    #[test]
    fn parse_until_sos_max_size_limits_scan() {
        let mut buf = vec![0xFF, markers::SOI];
        buf.extend(make_segment(markers::DQT, &[0; 4]));
        buf.extend(make_segment(markers::SOS, &[0; 4]));

        // Set max_size so small it cuts off before SOS
        let err = parse_until_sos(&buf, 0, 6).unwrap_err();
        assert!(matches!(err, ParseError::MissingSos | ParseError::OutOfBounds | ParseError::SegmentLengthOverflows { .. }));
    }

    #[test]
    fn parse_until_sos_random_noise() {
        let noise: Vec<u8> = (0..256).map(|i| (i * 37 % 256) as u8).collect();
        assert!(parse_until_sos(&noise, 0, noise.len()).is_err());
    }

    #[test]
    fn parse_until_sos_sof_zero_dimensions_rejected() {
        let mut buf = vec![0xFF, markers::SOI];
        // SOF0 with width=0
        let sof_payload = [0x08, 0x01, 0xE0, 0x00, 0x00, 0x03];
        buf.extend(make_segment(markers::SOF0, &sof_payload));
        buf.extend(make_segment(markers::SOS, &[0; 4]));

        let err = parse_until_sos(&buf, 0, buf.len()).unwrap_err();
        assert!(matches!(err, ParseError::BadSofPayload { .. }));
    }

    #[test]
    fn parse_until_sos_sof_payload_too_short() {
        let mut buf = vec![0xFF, markers::SOI];
        // SOF0 with only 3 bytes of payload (needs 6)
        let sof_payload = [0x08, 0x01, 0xE0];
        buf.extend(make_segment(markers::SOF0, &sof_payload));
        buf.extend(make_segment(markers::SOS, &[0; 4]));

        let err = parse_until_sos(&buf, 0, buf.len()).unwrap_err();
        assert!(matches!(err, ParseError::BadSofPayload { .. }));
    }
}
