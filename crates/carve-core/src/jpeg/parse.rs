// Pre-SOS segment parsing
use super::markers;
use super::util::be_u16;

#[inline]
pub fn be_u16(bytes: &[u8], i: usize) -> Option<u16> {
    let hi = *bytes.get(i)? as u16;
    let lo = *bytes.get(i + 1)? as u16;
    Some((hi << 8) | lo)
}

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
