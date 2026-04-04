use jpeg_decoder::{Decoder, PixelFormat};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecodeResult {
    pub success: bool,
    pub width: Option<u16>,
    pub height: Option<u16>,
    pub pixels: Option<Vec<u8>>,
}

pub fn decode_jpeg(bytes: &[u8]) -> DecodeResult {
    let mut decoder = Decoder::new(bytes);
    let pixels = match decoder.decode() {
        Ok(pixels) => pixels,
        Err(_) => return DecodeResult::default(),
    };

    let Some(info) = decoder.info() else {
        return DecodeResult::default();
    };

    let pixels = match info.pixel_format {
        PixelFormat::RGB24 => pixels,
        PixelFormat::L8 => grayscale_to_rgb(&pixels),
        PixelFormat::CMYK32 => cmyk_to_rgb(&pixels),
        _ => return DecodeResult::default(),
    };

    DecodeResult {
        success: true,
        width: Some(info.width),
        height: Some(info.height),
        pixels: Some(pixels),
    }
}

fn grayscale_to_rgb(pixels: &[u8]) -> Vec<u8> {
    let mut rgb = Vec::with_capacity(pixels.len() * 3);
    for &value in pixels {
        rgb.extend_from_slice(&[value, value, value]);
    }
    rgb
}

fn cmyk_to_rgb(pixels: &[u8]) -> Vec<u8> {
    let mut rgb = Vec::with_capacity((pixels.len() / 4) * 3);
    for chunk in pixels.chunks_exact(4) {
        let c = chunk[0] as u16;
        let m = chunk[1] as u16;
        let y = chunk[2] as u16;
        let k = chunk[3] as u16;

        let r = 255 - ((c * (255 - k) + 255 * k) / 255);
        let g = 255 - ((m * (255 - k) + 255 * k) / 255);
        let b = 255 - ((y * (255 - k) + 255 * k) / 255);
        rgb.extend_from_slice(&[r as u8, g as u8, b as u8]);
    }
    rgb
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_jpeg_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/examples/IMG_1373.jpg")
    }

    #[test]
    fn decodes_valid_jpeg_fixture() {
        let bytes = std::fs::read(example_jpeg_path()).unwrap();
        let result = decode_jpeg(&bytes);

        assert!(result.success);
        assert_eq!(result.width, Some(2992));
        assert_eq!(result.height, Some(2992));

        let pixels = result.pixels.as_ref().unwrap();
        assert_eq!(pixels.len(), 2992usize * 2992usize * 3usize);
    }

    #[test]
    fn returns_failure_for_corrupted_bytes() {
        let result = decode_jpeg(&[0x00; 64]);

        assert!(!result.success);
        assert_eq!(result.width, None);
        assert_eq!(result.height, None);
        assert_eq!(result.pixels, None);
    }
}
