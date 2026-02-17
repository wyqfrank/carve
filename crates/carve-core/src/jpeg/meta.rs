// SOF metadata extraction

/// Metadata extracted from the SOF segment.
#[derive(Debug, PartialEq)]
pub struct JpegFrameMeta {
    pub precision: u8,
    pub width: usize,
    pub height: usize,
    pub components: u8,
    pub is_progressive: bool
}

/// Errors that can occur while parsing SOF metadata.
#[derive(Debug, PartialEq)]
pub enum MetaError {
    PayloadTooShort,
    InvalidDimensions,
    UnreasonableBounds,
}


/// Parse SOF (SOF0 or SOF2) segment payload and extract metadata.
///
/// `payload` must begin immediately after the SOF segment length field.
/// `is_progressive_marker` should be true if marker was SOF2 (FF C2),
/// false if SOF0 (FF C0).
pub fn parse_sof_metadata(
    payload: &[u8], is_progressive_marker: bool
) -> Result<JpegFrameMeta, MetaError> {
    // Minimum SOF payload is 6 bytes:
    // [0] precision
    // [1..=2] height (big-endian u16)
    // [3..=4] width  (big-endian u16)
    // [5] components
    if payload.len() < 6 {return Err(MetaError::PayloadTooShort);}
    
    let precision = payload[0];
    let height = read_be_u16(payload, 1)? as usize;
    let width = read_be_u16(payload, 3)? as usize;
    let components = payload[5];

    // Validation: dimensions must be > 0
    if width == 0 || height == 0 {
        return Err(MetaError::InvalidDimensions);
    }

    // Validation: reasonable bounds
    // (prevent absurd allocations or corrupted values)
    if width > 100_000 || height > 100_000 {
        return Err(MetaError::UnreasonableBounds);
    }

    Ok(JpegFrameMeta {
        precision,
        width,
        height,
        components,
        is_progressive: is_progressive_marker,
    })
}

/// Read a big-endian u16 from payload at index `start`.
fn read_be_u16(payload: &[u8], start: usize) -> Result<u16, MetaError> {
    if start + 1 >= payload.len() {
        return Err(MetaError::PayloadTooShort);
    }
    let high = payload[start] as u16;
    let low = payload[start + 1] as u16;

    Ok((high << 8) | low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_sof0_metadata() {
        // [0] precision=8
        // [1..2] height=100 (0x0064)
        // [3..4] width=200 (0x00C8)
        // [5] components=3
        let payload = [0x08, 0x00, 0x64, 0x00, 0xC8, 0x03];
        let meta = parse_sof_metadata(&payload, false).unwrap();

        assert_eq!(meta.precision, 8);
        assert_eq!(meta.height, 100);
        assert_eq!(meta.width, 200);
        assert_eq!(meta.components, 3);
        assert!(!meta.is_progressive);
    }

    #[test]
    fn test_valid_sof2_progressive() {
        // Same payload, but flag=true
        let payload = [0x08, 0x00, 0x64, 0x00, 0xC8, 0x03];
        let meta = parse_sof_metadata(&payload, true).unwrap();
        assert!(meta.is_progressive);
    }

    #[test]
    fn test_payload_too_short() {
        let payload = [0x08, 0x00, 0x64]; // missing width+components
        let err = parse_sof_metadata(&payload, false).unwrap_err();
        assert_eq!(err, MetaError::PayloadTooShort);
    }

    #[test]
    fn test_invalid_dimensions_zero() {
        // width=0
        let payload = [0x08, 0x00, 0x64, 0x00, 0x00, 0x03];
        let err = parse_sof_metadata(&payload, false).unwrap_err();
        assert_eq!(err, MetaError::InvalidDimensions);

        // height=0
        let payload2 = [0x08, 0x00, 0x00, 0x00, 0xC8, 0x03];
        let err2 = parse_sof_metadata(&payload2, false).unwrap_err();
        assert_eq!(err2, MetaError::InvalidDimensions);
    }

    #[test]
    fn test_unreasonable_bounds_logic_check() {
        // Note: With u16, max is 65535, so > 100,000 is unreachable for 2-byte dimensions.
        // We verify that max u16 is accepted.
        // height=65535 (0xFFFF), width=65535 (0xFFFF)
        let payload = [0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x03];
        let meta = parse_sof_metadata(&payload, false).unwrap();
        assert_eq!(meta.height, 65535);
        assert_eq!(meta.width, 65535);
    }
}