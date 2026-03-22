use super::decode::DecodeResult;

#[derive(Debug, Clone, PartialEq)]
pub struct ImageMetrics {
    pub decode_success_score: f32,
    pub colour_balance: f32,
    pub pixel_entropy: f32,
    pub block_artifact_score: f32,
}

pub fn compute_image_metrics(decoded: &DecodeResult) -> ImageMetrics {
    if !decoded.success {
        return ImageMetrics::failed_decode();
    }

    let Some(width) = decoded.width else {
        return ImageMetrics::failed_decode();
    };
    let Some(height) = decoded.height else {
        return ImageMetrics::failed_decode();
    };
    let Some(pixels) = decoded.pixels.as_deref() else {
        return ImageMetrics::failed_decode();
    };

    let decode_success_score = if decoded.success { 1.0 } else { 0.0 };
    let colour_balance = compute_colour_balance(pixels);
    let pixel_entropy = compute_pixel_entropy(pixels);
    let block_artifact_score = compute_block_artifact_score(pixels, width, height);

    ImageMetrics {
        decode_success_score,
        colour_balance,
        pixel_entropy,
        block_artifact_score,
    }
}

pub fn compute_colour_balance(pixels: &[u8]) -> f32 {
    if pixels.len() < 3 {
        return 0.0;
    }

    let mut r_sum = 0f64;
    let mut g_sum = 0f64;
    let mut b_sum = 0f64;
    let mut count = 0usize;

    for chunk in pixels.chunks_exact(3) {
        r_sum += f64::from(chunk[0]);
        g_sum += f64::from(chunk[1]);
        b_sum += f64::from(chunk[2]);
        count += 1;
    }

    if count == 0 {
        return 0.0;
    }

    let r_mean = (r_sum / count as f64) as f32;
    let g_mean = (g_sum / count as f64) as f32;
    let b_mean = (b_sum / count as f64) as f32;
    let mean = (r_mean + g_mean + b_mean) / 3.0;

    if mean <= f32::EPSILON {
        return 1.0;
    }

    let variance = ((r_mean - mean).powi(2) + (g_mean - mean).powi(2) + (b_mean - mean).powi(2)) / 3.0;
    let std_dev = variance.sqrt();
    let max_std_dev = 255.0 * (2.0_f32 / 9.0_f32).sqrt();
    (1.0 - std_dev / max_std_dev).clamp(0.0, 1.0)
}

pub fn compute_pixel_entropy(pixels: &[u8]) -> f32 {
    if pixels.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &value in pixels {
        counts[value as usize] += 1;
    }

    let total = pixels.len() as f32;
    let entropy: f32 = counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f32 / total;
            -probability * probability.log2()
        })
        .sum();

    (entropy / 8.0).clamp(0.0, 1.0)
}

pub fn compute_block_artifact_score(pixels: &[u8], width: u16, height: u16) -> f32 {
    let row_len = width as usize * 3;
    let rows = height as usize;

    if row_len == 0 || rows == 0 {
        return 0.0;
    }

    if rows == 1 {
        return 1.0;
    }

    let expected_len = row_len * rows;
    if pixels.len() < expected_len {
        return 0.0;
    }

    let mut repeated_pairs = 0usize;
    let mut comparisons = 0usize;

    for row in 0..(rows - 1) {
        let current_start = row * row_len;
        let next_start = current_start + row_len;
        let current = &pixels[current_start..current_start + row_len];
        let next = &pixels[next_start..next_start + row_len];

        let avg_abs_diff = current
            .iter()
            .zip(next.iter())
            .map(|(&a, &b)| u32::from(a.abs_diff(b)))
            .sum::<u32>() as f32
            / row_len as f32;

        if avg_abs_diff <= 2.0 {
            repeated_pairs += 1;
        }
        comparisons += 1;
    }

    if comparisons == 0 {
        return 1.0;
    }

    (1.0 - repeated_pairs as f32 / comparisons as f32).clamp(0.0, 1.0)
}

impl ImageMetrics {
    fn failed_decode() -> Self {
        Self {
            decode_success_score: 0.0,
            colour_balance: 0.0,
            pixel_entropy: 0.0,
            block_artifact_score: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconstruct::decode::decode_jpeg;

    fn repeated_rows(width: u16, height: u16, row: [u8; 3]) -> Vec<u8> {
        let mut pixels = Vec::with_capacity(width as usize * height as usize * 3);
        for _ in 0..height {
            for _ in 0..width {
                pixels.extend_from_slice(&row);
            }
        }
        pixels
    }

    fn varied_rows(width: u16, height: u16) -> Vec<u8> {
        let mut pixels = Vec::with_capacity(width as usize * height as usize * 3);
        for y in 0..height {
            for x in 0..width {
                pixels.push(((x * 17 + y * 3) % 256) as u8);
                pixels.push(((x * 7 + y * 29) % 256) as u8);
                pixels.push(((x * 11 + y * 13) % 256) as u8);
            }
        }
        pixels
    }

    fn example_jpeg_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/examples/IMG_1373.jpg")
    }

    #[test]
    fn colour_balance_penalises_strong_colour_cast() {
        let neutral = vec![120, 118, 121, 100, 99, 101, 140, 138, 141];
        let red_cast = vec![255, 0, 0, 240, 5, 10, 245, 8, 12];

        assert!(compute_colour_balance(&neutral) > compute_colour_balance(&red_cast));
    }

    #[test]
    fn pixel_entropy_rewards_varied_pixels() {
        let flat = vec![42u8; 4096];
        let varied: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();

        assert!(compute_pixel_entropy(&varied) > compute_pixel_entropy(&flat));
    }

    #[test]
    fn block_artifact_score_penalises_repeated_rows() {
        let repeated = repeated_rows(16, 8, [64, 64, 64]);
        let varied = varied_rows(16, 8);

        assert!(compute_block_artifact_score(&varied, 16, 8) > compute_block_artifact_score(&repeated, 16, 8));
    }

    #[test]
    fn failed_decode_produces_zero_scores() {
        let failed = DecodeResult::default();
        let metrics = compute_image_metrics(&failed);

        assert_eq!(
            metrics,
            ImageMetrics {
                decode_success_score: 0.0,
                colour_balance: 0.0,
                pixel_entropy: 0.0,
                block_artifact_score: 0.0,
            }
        );
    }

    #[test]
    fn decoded_fixture_produces_stable_metric_ranges() {
        let bytes = std::fs::read(example_jpeg_path()).unwrap();
        let decoded = decode_jpeg(&bytes);
        let metrics = compute_image_metrics(&decoded);

        assert_eq!(metrics.decode_success_score, 1.0);
        assert!((0.0..=1.0).contains(&metrics.colour_balance));
        assert!((0.0..=1.0).contains(&metrics.pixel_entropy));
        assert!((0.0..=1.0).contains(&metrics.block_artifact_score));
        assert!(metrics.pixel_entropy > 0.1);
    }
}
