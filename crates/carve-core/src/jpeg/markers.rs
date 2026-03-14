// JPEG marker constants and helpers
pub const SOI: u8 = 0xD8; // Start of image
pub const EOI: u8 = 0xD9; // End of image
pub const SOS: u8 = 0xDA; // Start of scan

pub const SOF0: u8 = 0xC0; // baseline
pub const SOF2: u8 = 0xC2; // progressive

pub const DQT: u8 = 0xDB; // Define quantization table
pub const DHT: u8 = 0xC4; // Define Huffman Table

pub const COM: u8 = 0xFE; // Comment

#[inline]
pub fn is_app(marker: u8) -> bool {
    (0xE0..=0xEF).contains(&marker)
}

#[inline]
pub fn is_restart(marker: u8) -> bool {
    (0xD0..=0xD7).contains(&marker)
}

/// Markers that do NOT have a length field.
#[inline]
pub fn has_length(marker: u8) -> bool {
    // SOI/EOI/RSTn/TEM do not have lengths.
    if marker == SOI || marker == EOI || is_restart(marker) || marker == 0x01 {
        return false;
    }
    true
}