// SOF metadata extraction

/// Metadata extracted from the SOF segment.
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
    InvalidDemensions,
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
