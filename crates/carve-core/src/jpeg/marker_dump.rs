// JPEG marker dump utility
//
// Parses a JPEG header from SOI through SOS (inclusive) and returns a
// structured list of every segment encountered, including raw payload bytes.
// Intended for inspecting reference images to build camera-specific profiles.

use super::markers;
use super::parse::{parse_segment, read_marker, ParseError};

/// Human-readable name for a JPEG marker byte.
pub fn marker_name(marker: u8) -> &'static str {
    match marker {
        0xD8 => "SOI",
        0xD9 => "EOI",
        0xDA => "SOS",
        0xC0 => "SOF0",
        0xC1 => "SOF1",
        0xC2 => "SOF2",
        0xC3 => "SOF3",
        0xC4 => "DHT",
        0xC5 => "SOF5",
        0xC6 => "SOF6",
        0xC7 => "SOF7",
        0xC9 => "SOF9",
        0xCA => "SOF10",
        0xCB => "SOF11",
        0xCC => "DAC",
        0xDB => "DQT",
        0xDC => "DNL",
        0xDD => "DRI",
        0xDE => "DHP",
        0xDF => "EXP",
        0xE0 => "APP0",
        0xE1 => "APP1",
        0xE2 => "APP2",
        0xE3 => "APP3",
        0xE4 => "APP4",
        0xE5 => "APP5",
        0xE6 => "APP6",
        0xE7 => "APP7",
        0xE8 => "APP8",
        0xE9 => "APP9",
        0xEA => "APP10",
        0xEB => "APP11",
        0xEC => "APP12",
        0xED => "APP13",
        0xEE => "APP14",
        0xEF => "APP15",
        0xFE => "COM",
        _ => "UNKNOWN",
    }
}

/// A single parsed JPEG segment with its raw payload bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct SegmentDump {
    /// Marker byte (e.g. `0xE0` for APP0, `0xDB` for DQT).
    pub marker: u8,
    /// Human-readable marker name.
    pub name: &'static str,
    /// Byte offset of the `0xFF` prefix byte in the source buffer.
    pub offset: usize,
    /// Number of payload bytes (excludes the 2-byte marker + 2-byte length field).
    pub payload_len: usize,
    /// Raw payload bytes (empty for SOI which has no length field).
    pub payload: Vec<u8>,
}

/// All segments parsed from a JPEG header, SOI inclusive through SOS inclusive.
#[derive(Debug, Clone)]
pub struct JpegDump {
    pub segments: Vec<SegmentDump>,
}

impl JpegDump {
    /// Format the dump as a human-readable table suitable for terminal output.
    ///
    /// Each line shows: `offset  marker  name  payload_len  payload_preview`
    pub fn to_debug_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "  {:<8}  {:<6}  {:<8}  {:<10}  {}\n",
            "offset", "marker", "name", "payload", "payload preview (first 8 bytes)"
        ));
        out.push_str(&format!(
            "  {:-<8}  {:-<6}  {:-<8}  {:-<10}  {:-<32}\n",
            "", "", "", "", ""
        ));
        for seg in &self.segments {
            let preview = if seg.payload.is_empty() {
                String::new()
            } else {
                let n = seg.payload.len().min(8);
                let hex: Vec<String> = seg.payload[..n]
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect();
                let suffix = if seg.payload_len > 8 { " ..." } else { "" };
                format!("[{}{}]", hex.join(" "), suffix)
            };
            out.push_str(&format!(
                "  {:<8}  FF {:02X}   {:<8}  {:<10}  {}\n",
                format!("0x{:04X}", seg.offset),
                seg.marker,
                seg.name,
                seg.payload_len,
                preview,
            ));
        }
        out
    }

    /// Serialise the dump as a JSON array.
    ///
    /// The `payload_hex` field contains the full segment payload as an
    /// uppercase hex string — useful for comparing tables across cameras.
    pub fn to_json(&self) -> String {
        let mut out = String::from("[\n");
        for (i, seg) in self.segments.iter().enumerate() {
            let payload_hex: String = seg
                .payload
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect();
            let comma = if i + 1 < self.segments.len() { "," } else { "" };
            out.push_str(&format!(
                "  {{\"marker\":\"0x{:02X}\",\"name\":\"{}\",\"offset\":{},\"payload_len\":{},\"payload_hex\":\"{}\"}}{}\n",
                seg.marker,
                seg.name,
                seg.offset,
                seg.payload_len,
                payload_hex,
                comma,
            ));
        }
        out.push(']');
        out
    }
}

/// Parse a JPEG header and return a dump of every segment from SOI through SOS.
///
/// Parsing begins at `start` and reads until SOS (inclusive).  Entropy data
/// after SOS is intentionally not touched.  Returns `ParseError` for any
/// structural problem: wrong magic bytes, missing SOS, unexpected markers,
/// truncated segments, etc.
pub fn dump_jpeg_segments(bytes: &[u8], start: usize) -> Result<JpegDump, ParseError> {
    let limit = bytes.len();

    if start + 2 > limit {
        return Err(ParseError::OutOfBounds);
    }
    if bytes[start] != 0xFF || bytes[start + 1] != markers::SOI {
        return Err(ParseError::NotJpeg);
    }

    let mut segments = Vec::new();

    // SOI itself: 2 bytes, no payload, no length field.
    segments.push(SegmentDump {
        marker: markers::SOI,
        name: marker_name(markers::SOI),
        offset: start,
        payload_len: 0,
        payload: Vec::new(),
    });

    let mut pos = start + 2;

    loop {
        let (marker, marker_pos, next_pos) = read_marker(bytes, pos, limit)?;

        // These markers must not appear inside a JPEG header.
        if markers::is_restart(marker) || marker == markers::SOI || marker == markers::EOI {
            return Err(ParseError::InvalidMarkerStream { at: marker_pos });
        }

        if !markers::has_length(marker) {
            return Err(ParseError::InvalidMarkerStream { at: marker_pos });
        }

        let parsed = parse_segment(bytes, marker, marker_pos, next_pos, limit)?;
        let payload = bytes[parsed.payload_pos..parsed.seg_end].to_vec();

        segments.push(SegmentDump {
            marker,
            name: marker_name(marker),
            offset: marker_pos,
            payload_len: parsed.payload_len,
            payload,
        });

        // Stop after SOS — do not attempt to parse entropy data as segments.
        if marker == markers::SOS {
            break;
        }

        pos = parsed.seg_end;
    }

    Ok(JpegDump { segments })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::markers;

    // ---------------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------------

    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        let mut v = vec![0xFF, marker, (len >> 8) as u8, len as u8];
        v.extend_from_slice(payload);
        v
    }

    fn minimal_jpeg() -> Vec<u8> {
        let mut buf = vec![0xFF, markers::SOI];
        buf.extend(seg(markers::DQT, &[0u8; 4]));
        buf.extend(seg(markers::SOS, &[0u8; 4]));
        buf
    }

    // ---------------------------------------------------------------------------
    // marker_name
    // ---------------------------------------------------------------------------

    #[test]
    fn known_marker_names_are_correct() {
        assert_eq!(marker_name(0xD8), "SOI");
        assert_eq!(marker_name(0xD9), "EOI");
        assert_eq!(marker_name(0xDA), "SOS");
        assert_eq!(marker_name(0xC0), "SOF0");
        assert_eq!(marker_name(0xC2), "SOF2");
        assert_eq!(marker_name(0xC4), "DHT");
        assert_eq!(marker_name(0xDB), "DQT");
        assert_eq!(marker_name(0xDD), "DRI");
        assert_eq!(marker_name(0xE0), "APP0");
        assert_eq!(marker_name(0xE1), "APP1");
        assert_eq!(marker_name(0xFE), "COM");
    }

    #[test]
    fn unknown_marker_returns_unknown() {
        assert_eq!(marker_name(0x00), "UNKNOWN");
        assert_eq!(marker_name(0xAB), "UNKNOWN");
    }

    // ---------------------------------------------------------------------------
    // dump_jpeg_segments — structure
    // ---------------------------------------------------------------------------

    #[test]
    fn minimal_jpeg_produces_three_segments() {
        let data = minimal_jpeg();
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        // SOI + DQT + SOS
        assert_eq!(dump.segments.len(), 3);
    }

    #[test]
    fn first_segment_is_soi_with_no_payload() {
        let data = minimal_jpeg();
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let soi = &dump.segments[0];
        assert_eq!(soi.marker, markers::SOI);
        assert_eq!(soi.name, "SOI");
        assert_eq!(soi.offset, 0);
        assert_eq!(soi.payload_len, 0);
        assert!(soi.payload.is_empty());
    }

    #[test]
    fn last_segment_is_sos() {
        let data = minimal_jpeg();
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let sos = dump.segments.last().unwrap();
        assert_eq!(sos.marker, markers::SOS);
        assert_eq!(sos.name, "SOS");
    }

    #[test]
    fn dqt_segment_has_correct_payload() {
        let payload = [0xAAu8; 64];
        let mut data = vec![0xFF, markers::SOI];
        data.extend(seg(markers::DQT, &payload));
        data.extend(seg(markers::SOS, &[0u8; 4]));

        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let dqt = &dump.segments[1];
        assert_eq!(dqt.marker, markers::DQT);
        assert_eq!(dqt.name, "DQT");
        assert_eq!(dqt.payload_len, 64);
        assert_eq!(dqt.payload, payload);
    }

    #[test]
    fn segment_offset_is_position_of_ff_byte() {
        // SOI occupies bytes 0-1, DQT starts at byte 2.
        let data = minimal_jpeg();
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        assert_eq!(dump.segments[1].offset, 2); // DQT at byte 2
    }

    #[test]
    fn nonzero_start_is_respected() {
        let prefix = vec![0xDEu8; 16];
        let mut data = prefix.clone();
        data.extend(minimal_jpeg());
        let dump = dump_jpeg_segments(&data, 16).unwrap();
        assert_eq!(dump.segments[0].offset, 16); // SOI at byte 16
    }

    #[test]
    fn stops_at_sos_does_not_parse_entropy() {
        // Append entropy data that contains a valid DQT marker — must be ignored.
        let mut data = minimal_jpeg();
        data.extend(seg(markers::DQT, &[0u8; 4])); // this is entropy / after SOS
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        // Still only SOI + DQT + SOS (entropy DQT is not parsed)
        assert_eq!(dump.segments.len(), 3);
    }

    // ---------------------------------------------------------------------------
    // dump_jpeg_segments — marker ordering and recognition
    // ---------------------------------------------------------------------------

    #[test]
    fn all_standard_header_markers_are_captured() {
        let mut data = vec![0xFF, markers::SOI];

        // APP0
        data.extend(seg(0xE0, b"JFIF\0\x01\x01\0\0\x48\0\x48\0\0"));
        // APP1 (Exif)
        let mut exif = b"Exif\0\0".to_vec();
        exif.extend_from_slice(&[0u8; 8]);
        data.extend(seg(0xE1, &exif));
        // DQT
        data.extend(seg(markers::DQT, &[0u8; 64]));
        // DHT
        data.extend(seg(markers::DHT, &[0u8; 20]));
        // DRI
        data.extend(seg(0xDD, &[0x00, 0x20])); // restart every 32 MCUs
        // SOF0
        let sof = [0x08, 0x04, 0x38, 0x07, 0x80, 0x03,
                   0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01];
        data.extend(seg(markers::SOF0, &sof));
        // SOS
        data.extend(seg(markers::SOS, &[0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00]));

        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let names: Vec<&str> = dump.segments.iter().map(|s| s.name).collect();
        assert_eq!(names, ["SOI", "APP0", "APP1", "DQT", "DHT", "DRI", "SOF0", "SOS"]);
    }

    #[test]
    fn dri_payload_is_captured() {
        let mut data = vec![0xFF, markers::SOI];
        data.extend(seg(0xDD, &[0x00, 0x40])); // DRI: restart interval = 64
        data.extend(seg(markers::SOS, &[0u8; 4]));

        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let dri = dump.segments.iter().find(|s| s.marker == 0xDD).unwrap();
        assert_eq!(dri.name, "DRI");
        assert_eq!(dri.payload_len, 2);
        assert_eq!(dri.payload, vec![0x00, 0x40]);
    }

    // ---------------------------------------------------------------------------
    // dump_jpeg_segments — error cases
    // ---------------------------------------------------------------------------

    #[test]
    fn empty_input_returns_out_of_bounds() {
        assert!(matches!(
            dump_jpeg_segments(&[], 0),
            Err(ParseError::OutOfBounds)
        ));
    }

    #[test]
    fn non_jpeg_returns_not_jpeg() {
        assert!(matches!(
            dump_jpeg_segments(&[0x00, 0x01, 0x02, 0x03], 0),
            Err(ParseError::NotJpeg)
        ));
    }

    #[test]
    fn missing_sos_returns_missing_sos() {
        let mut data = vec![0xFF, markers::SOI];
        data.extend(seg(markers::DQT, &[0u8; 4]));
        // No SOS
        assert!(matches!(
            dump_jpeg_segments(&data, 0),
            Err(ParseError::MissingSos | ParseError::OutOfBounds)
        ));
    }

    #[test]
    fn rst_marker_in_header_returns_error() {
        let data = [0xFF, markers::SOI, 0xFF, 0xD0]; // RST0 before SOS
        assert!(matches!(
            dump_jpeg_segments(&data, 0),
            Err(ParseError::InvalidMarkerStream { .. })
        ));
    }

    #[test]
    fn eoi_before_sos_returns_error() {
        let data = [0xFF, markers::SOI, 0xFF, markers::EOI];
        assert!(matches!(
            dump_jpeg_segments(&data, 0),
            Err(ParseError::InvalidMarkerStream { .. })
        ));
    }

    #[test]
    fn truncated_segment_length_returns_error() {
        // DQT with declared length 200 but file ends after 6 bytes
        let data = [0xFF, markers::SOI, 0xFF, markers::DQT, 0x00, 0xC8];
        assert!(matches!(
            dump_jpeg_segments(&data, 0),
            Err(ParseError::SegmentLengthOverflows { .. } | ParseError::OutOfBounds)
        ));
    }

    // ---------------------------------------------------------------------------
    // to_debug_text
    // ---------------------------------------------------------------------------

    #[test]
    fn debug_text_contains_marker_names() {
        let data = minimal_jpeg();
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let text = dump.to_debug_text();
        assert!(text.contains("SOI"));
        assert!(text.contains("DQT"));
        assert!(text.contains("SOS"));
    }

    #[test]
    fn debug_text_contains_offsets() {
        let data = minimal_jpeg();
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let text = dump.to_debug_text();
        // SOI is at offset 0x0000, DQT at 0x0002
        assert!(text.contains("0x0000"));
        assert!(text.contains("0x0002"));
    }

    #[test]
    fn debug_text_shows_payload_preview() {
        let mut data = vec![0xFF, markers::SOI];
        data.extend(seg(markers::DQT, &[0xABu8; 64]));
        data.extend(seg(markers::SOS, &[0u8; 4]));

        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let text = dump.to_debug_text();
        // Preview should include the first byte of the DQT payload
        assert!(text.contains("AB"));
        // And indicate there are more bytes
        assert!(text.contains("..."));
    }

    // ---------------------------------------------------------------------------
    // to_json
    // ---------------------------------------------------------------------------

    #[test]
    fn json_is_valid_array_syntax() {
        let data = minimal_jpeg();
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let json = dump.to_json();
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
    }

    #[test]
    fn json_contains_expected_fields() {
        let data = minimal_jpeg();
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let json = dump.to_json();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"offset\""));
        assert!(json.contains("\"payload_len\""));
        assert!(json.contains("\"payload_hex\""));
    }

    #[test]
    fn json_encodes_dqt_payload_as_hex() {
        let mut data = vec![0xFF, markers::SOI];
        data.extend(seg(markers::DQT, &[0xAB, 0xCD]));
        data.extend(seg(markers::SOS, &[0u8; 4]));

        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let json = dump.to_json();
        assert!(json.contains("ABCD"));
    }

    #[test]
    fn json_contains_soi_entry() {
        let data = minimal_jpeg();
        let dump = dump_jpeg_segments(&data, 0).unwrap();
        let json = dump.to_json();
        assert!(json.contains("\"SOI\""));
    }
}
