use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::jpeg::parse::{parse_until_sos, parse_until_sos_no_soi};
use crate::jpeg::validate::ValidatedCandidate;
use super::camera_profile::CameraJpegProfile;
use super::header_builder::build_header;

const EOI_MARKER: [u8; 2] = [0xFF, 0xD9];

#[derive(Debug)]
pub struct RebuildError(io::Error);

impl std::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rebuild error: {}", self.0)
    }
}

impl From<io::Error> for RebuildError {
    fn from(e: io::Error) -> Self {
        Self(e)
    }
}

/// Options for the entropy offset search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetSearchOptions {
    /// Maximum byte offset into the entropy stream to try (inclusive).
    ///
    /// The search produces one rebuilt JPEG per offset from `0` to
    /// `max_offset` (stepping by `step`).  Default: 512.
    pub max_offset: usize,
    /// Step size between successive offsets.  Default: 1.
    pub step: usize,
}

impl Default for OffsetSearchOptions {
    fn default() -> Self {
        Self { max_offset: 512, step: 1 }
    }
}

/// Locate the entropy stream bounds for a candidate.
///
/// Returns `(scan_start, entropy_end)` where:
/// - `scan_start` is the first byte of entropy data (after the SOS payload).
/// - `entropy_end` is the exclusive end of entropy data (EOI excluded).
///
/// Returns `None` if re-parsing fails or the bounds are invalid.
fn resolve_entropy_bounds(
    bytes: &[u8],
    candidate: &ValidatedCandidate,
) -> Option<(usize, usize)> {
    let max_size = bytes.len();
    let pre_sos = if candidate.missing_soi {
        parse_until_sos_no_soi(bytes, candidate.start, max_size).ok()?
    } else {
        parse_until_sos(bytes, candidate.start, max_size).ok()?
    };

    let scan_start = pre_sos.scan_start;

    // Strip existing EOI when present; for truncated candidates there is none.
    let entropy_end = if candidate.patched_eoi {
        candidate.end
    } else {
        candidate.end.saturating_sub(2)
    };

    if scan_start >= entropy_end || entropy_end > bytes.len() {
        return None;
    }

    Some((scan_start, entropy_end))
}

/// Rebuild each candidate as a `rebuilt_NNN.jpg` file using a camera-specific header.
///
/// For each candidate with known dimensions, this function:
/// 1. Re-parses the pre-SOS header to locate the entropy stream start.
/// 2. Extracts the raw entropy bytes.
/// 3. Prepends a synthesized header built from `profile`.
/// 4. Appends an EOI marker.
///
/// Candidates without known dimensions, or that fail re-parsing, are skipped
/// and produce a `None` entry in the returned vector.
///
/// Output files are named `rebuilt_000.jpg`, `rebuilt_001.jpg`, … matching
/// the indices of `extract_candidates`'s `recovered_NNN.jpg` output so Phase 1
/// and Phase 2 results are easy to compare side-by-side.
pub fn rebuild_candidates(
    bytes: &[u8],
    candidates: &[ValidatedCandidate],
    profile: &CameraJpegProfile,
    output_dir: &Path,
) -> Result<Vec<Option<PathBuf>>, RebuildError> {
    let mut paths = Vec::with_capacity(candidates.len());

    for (i, candidate) in candidates.iter().enumerate() {
        let (width, height) = match (candidate.width, candidate.height) {
            (Some(w), Some(h)) => (w, h),
            _ => { paths.push(None); continue; }
        };

        let (scan_start, entropy_end) = match resolve_entropy_bounds(bytes, candidate) {
            Some(b) => b,
            None => { paths.push(None); continue; }
        };

        let entropy = &bytes[scan_start..entropy_end];
        let header = build_header(profile, width, height);

        let filename = format!("rebuilt_{:03}.jpg", i);
        let path = output_dir.join(&filename);
        write_jpeg(&path, &header, entropy)?;

        paths.push(Some(path));
    }

    Ok(paths)
}

/// For each candidate, generate one rebuilt JPEG per offset in the search range.
///
/// The entropy stream is sliced from `scan_start + offset` to `entropy_end`
/// for each offset in `0..=options.max_offset` stepping by `options.step`.
/// Offsets that exhaust the entropy stream are silently skipped.
///
/// Output files are named `rebuilt_NNN_offset_MMMM.jpg` where `NNN` is the
/// candidate index (zero-padded to 3 digits) and `MMMM` is the byte offset
/// (zero-padded to 4 digits).  Candidates without known dimensions produce an
/// empty inner `Vec`.
pub fn rebuild_with_offset_search(
    bytes: &[u8],
    candidates: &[ValidatedCandidate],
    profile: &CameraJpegProfile,
    output_dir: &Path,
    options: &OffsetSearchOptions,
) -> Result<Vec<Vec<PathBuf>>, RebuildError> {
    let step = options.step.max(1);
    let mut result = Vec::with_capacity(candidates.len());

    for (i, candidate) in candidates.iter().enumerate() {
        let (width, height) = match (candidate.width, candidate.height) {
            (Some(w), Some(h)) => (w, h),
            _ => { result.push(Vec::new()); continue; }
        };

        let (scan_start, entropy_end) = match resolve_entropy_bounds(bytes, candidate) {
            Some(b) => b,
            None => { result.push(Vec::new()); continue; }
        };

        let header = build_header(profile, width, height);
        let mut paths = Vec::new();
        let mut offset = 0usize;

        loop {
            let entropy_start = scan_start + offset;
            if entropy_start >= entropy_end {
                break;
            }

            let entropy = &bytes[entropy_start..entropy_end];
            let filename = format!("rebuilt_{:03}_offset_{:04}.jpg", i, offset);
            let path = output_dir.join(&filename);
            write_jpeg(&path, &header, entropy)?;
            paths.push(path);

            if offset >= options.max_offset {
                break;
            }
            offset = (offset + step).min(options.max_offset);
        }

        result.push(paths);
    }

    Ok(result)
}

/// Write a single rebuilt JPEG: `header + entropy + EOI`.
fn write_jpeg(path: &Path, header: &[u8], entropy: &[u8]) -> Result<(), RebuildError> {
    let file = std::fs::File::create(path)?;
    let mut writer = io::BufWriter::new(file);
    writer.write_all(header)?;
    writer.write_all(entropy)?;
    writer.write_all(&EOI_MARKER)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jpeg::candidate::RecoveryStatus;
    use crate::jpeg::markers;
    use crate::reconstruct::camera_profile::CameraJpegProfile;

    fn temp_subdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("carve_rebuild_test_{}", name));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        let mut v = vec![0xFF, marker, (len >> 8) as u8, len as u8];
        v.extend_from_slice(payload);
        v
    }

    /// Minimal but valid JPEG bytes with known dimensions.
    fn make_valid_jpeg(width: u16, height: u16) -> Vec<u8> {
        let mut buf = vec![0xFF, markers::SOI];
        // DQT
        let mut dqt = vec![0x00u8];
        dqt.extend_from_slice(&[16u8; 64]);
        buf.extend(make_segment(markers::DQT, &dqt));
        // SOF0
        let h = height.to_be_bytes();
        let w = width.to_be_bytes();
        let sof = [0x08, h[0], h[1], w[0], w[1], 0x03,
                   0x01, 0x21, 0x00,
                   0x02, 0x11, 0x01,
                   0x03, 0x11, 0x01];
        buf.extend(make_segment(markers::SOF0, &sof));
        // SOS
        let sos = [0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00];
        buf.extend(make_segment(markers::SOS, &sos));
        // entropy + EOI
        buf.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x12, 0x34]);
        buf.extend_from_slice(&[0xFF, 0xD9]);
        buf
    }

    fn make_candidate(
        start: usize,
        end: usize,
        patched_eoi: bool,
        missing_soi: bool,
        width: Option<u16>,
        height: Option<u16>,
    ) -> ValidatedCandidate {
        ValidatedCandidate {
            start,
            end,
            status: if patched_eoi { RecoveryStatus::Truncated } else { RecoveryStatus::Recovered },
            patched_eoi,
            missing_soi,
            confidence_score: 0.9,
            has_exif: false,
            has_dqt: true,
            has_dht: false,
            width,
            height,
            is_progressive: Some(false),
            last_rst_marker: None,
        }
    }

    fn profile() -> CameraJpegProfile {
        CameraJpegProfile::canon_ixus_310hs()
    }

    // ---- rebuild_candidates tests ----

    #[test]
    fn rebuilt_file_starts_with_soi_ends_with_eoi() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, Some(320), Some(240));
        let dir = temp_subdir("soi_eoi");
        let paths = rebuild_candidates(&jpeg, &[candidate], &profile(), &dir).unwrap();
        assert_eq!(paths.len(), 1);
        let path = paths[0].as_ref().expect("should produce a file");
        let out = std::fs::read(path).unwrap();
        assert_eq!(&out[..2], &[0xFF, 0xD8], "must start with SOI");
        assert_eq!(&out[out.len() - 2..], &[0xFF, 0xD9], "must end with EOI");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn output_filename_matches_index() {
        let jpeg = make_valid_jpeg(100, 100);
        let end = jpeg.len();
        let candidates = vec![
            make_candidate(0, end, false, false, Some(100), Some(100)),
        ];
        let dir = temp_subdir("naming");
        let paths = rebuild_candidates(&jpeg, &candidates, &profile(), &dir).unwrap();
        assert_eq!(paths[0].as_ref().unwrap().file_name().unwrap(), "rebuilt_000.jpg");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn candidate_without_dimensions_is_skipped() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, None, None);
        let dir = temp_subdir("no_dims");
        let paths = rebuild_candidates(&jpeg, &[candidate], &profile(), &dir).unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn candidate_with_partial_dimensions_is_skipped() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, Some(320), None);
        let dir = temp_subdir("partial_dims");
        let paths = rebuild_candidates(&jpeg, &[candidate], &profile(), &dir).unwrap();
        assert!(paths[0].is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rebuilt_sof0_contains_candidate_dimensions() {
        let jpeg = make_valid_jpeg(640, 480);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, Some(640), Some(480));
        let dir = temp_subdir("dims_in_sof0");
        let paths = rebuild_candidates(&jpeg, &[candidate], &profile(), &dir).unwrap();
        let out = std::fs::read(paths[0].as_ref().unwrap()).unwrap();

        let sof0_pos = out.windows(2).position(|w| w == [0xFF, 0xC0]).expect("SOF0 not found");
        let h = u16::from_be_bytes([out[sof0_pos + 5], out[sof0_pos + 6]]);
        let w = u16::from_be_bytes([out[sof0_pos + 7], out[sof0_pos + 8]]);
        assert_eq!(w, 640);
        assert_eq!(h, 480);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_candidate_with_patched_eoi_gets_eoi_appended() {
        let mut jpeg = make_valid_jpeg(320, 240);
        jpeg.truncate(jpeg.len() - 2);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, true, false, Some(320), Some(240));
        let dir = temp_subdir("truncated");
        let paths = rebuild_candidates(&jpeg, &[candidate], &profile(), &dir).unwrap();
        let out = std::fs::read(paths[0].as_ref().unwrap()).unwrap();
        assert_eq!(&out[out.len() - 2..], &[0xFF, 0xD9]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiple_candidates_get_sequential_filenames() {
        let jpeg0 = make_valid_jpeg(320, 240);
        let jpeg1 = make_valid_jpeg(640, 480);
        let mut bytes = jpeg0.clone();
        let offset = bytes.len();
        bytes.extend_from_slice(&jpeg1);

        let candidates = vec![
            make_candidate(0, jpeg0.len(), false, false, Some(320), Some(240)),
            make_candidate(offset, offset + jpeg1.len(), false, false, Some(640), Some(480)),
        ];
        let dir = temp_subdir("multi");
        let paths = rebuild_candidates(&bytes, &candidates, &profile(), &dir).unwrap();
        assert_eq!(paths[0].as_ref().unwrap().file_name().unwrap(), "rebuilt_000.jpg");
        assert_eq!(paths[1].as_ref().unwrap().file_name().unwrap(), "rebuilt_001.jpg");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_candidates_returns_empty_vec() {
        let bytes = vec![0u8; 16];
        let dir = temp_subdir("empty");
        let paths = rebuild_candidates(&bytes, &[], &profile(), &dir).unwrap();
        assert!(paths.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn skipped_slot_index_preserved_in_output_vec() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidates = vec![
            make_candidate(0, end, false, false, None, None),
            make_candidate(0, end, false, false, Some(320), Some(240)),
        ];
        let dir = temp_subdir("skip_idx");
        let paths = rebuild_candidates(&jpeg, &candidates, &profile(), &dir).unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths[0].is_none());
        assert!(paths[1].is_some());
        assert_eq!(paths[1].as_ref().unwrap().file_name().unwrap(), "rebuilt_001.jpg");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- rebuild_with_offset_search tests ----

    #[test]
    fn offset_search_zero_max_offset_produces_one_file() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, Some(320), Some(240));
        let dir = temp_subdir("offset_zero");
        let opts = OffsetSearchOptions { max_offset: 0, step: 1 };
        let result = rebuild_with_offset_search(&jpeg, &[candidate], &profile(), &dir, &opts).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].len(), 1, "max_offset=0 should produce exactly one file (offset 0)");
        assert_eq!(result[0][0].file_name().unwrap(), "rebuilt_000_offset_0000.jpg");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_search_filename_encodes_offset() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, Some(320), Some(240));
        let dir = temp_subdir("offset_names");
        let opts = OffsetSearchOptions { max_offset: 2, step: 1 };
        let result = rebuild_with_offset_search(&jpeg, &[candidate], &profile(), &dir, &opts).unwrap();
        // entropy is 5 bytes (0xAB 0xCD 0xEF 0x12 0x34), so offsets 0,1,2 are all valid
        assert_eq!(result[0].len(), 3);
        assert_eq!(result[0][0].file_name().unwrap(), "rebuilt_000_offset_0000.jpg");
        assert_eq!(result[0][1].file_name().unwrap(), "rebuilt_000_offset_0001.jpg");
        assert_eq!(result[0][2].file_name().unwrap(), "rebuilt_000_offset_0002.jpg");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_search_each_file_starts_with_soi_ends_with_eoi() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, Some(320), Some(240));
        let dir = temp_subdir("offset_soi_eoi");
        let opts = OffsetSearchOptions { max_offset: 2, step: 1 };
        let result = rebuild_with_offset_search(&jpeg, &[candidate], &profile(), &dir, &opts).unwrap();
        for path in &result[0] {
            let out = std::fs::read(path).unwrap();
            assert_eq!(&out[..2], &[0xFF, 0xD8]);
            assert_eq!(&out[out.len() - 2..], &[0xFF, 0xD9]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_search_later_offset_produces_shorter_entropy() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, Some(320), Some(240));
        let dir = temp_subdir("offset_shorter");
        let opts = OffsetSearchOptions { max_offset: 2, step: 1 };
        let result = rebuild_with_offset_search(&jpeg, &[candidate], &profile(), &dir, &opts).unwrap();
        let len0 = std::fs::read(&result[0][0]).unwrap().len();
        let len2 = std::fs::read(&result[0][2]).unwrap().len();
        assert!(len2 < len0, "larger offset → fewer entropy bytes → smaller file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_search_stops_when_entropy_exhausted() {
        // Entropy is only 5 bytes; asking for max_offset=10 should stop early.
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, Some(320), Some(240));
        let dir = temp_subdir("offset_exhaust");
        let opts = OffsetSearchOptions { max_offset: 10, step: 1 };
        let result = rebuild_with_offset_search(&jpeg, &[candidate], &profile(), &dir, &opts).unwrap();
        // entropy has 5 bytes; valid offsets are 0..=4
        assert_eq!(result[0].len(), 5, "should stop at offset 4 (last byte)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_search_step_controls_spacing() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, Some(320), Some(240));
        let dir = temp_subdir("offset_step");
        let opts = OffsetSearchOptions { max_offset: 4, step: 2 };
        let result = rebuild_with_offset_search(&jpeg, &[candidate], &profile(), &dir, &opts).unwrap();
        // offsets tried: 0, 2, 4
        assert_eq!(result[0].len(), 3);
        assert_eq!(result[0][0].file_name().unwrap(), "rebuilt_000_offset_0000.jpg");
        assert_eq!(result[0][1].file_name().unwrap(), "rebuilt_000_offset_0002.jpg");
        assert_eq!(result[0][2].file_name().unwrap(), "rebuilt_000_offset_0004.jpg");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_search_candidate_without_dims_produces_empty_inner_vec() {
        let jpeg = make_valid_jpeg(320, 240);
        let end = jpeg.len();
        let candidate = make_candidate(0, end, false, false, None, None);
        let dir = temp_subdir("offset_no_dims");
        let opts = OffsetSearchOptions::default();
        let result = rebuild_with_offset_search(&jpeg, &[candidate], &profile(), &dir, &opts).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_search_empty_candidates_returns_empty_vec() {
        let bytes = vec![0u8; 16];
        let dir = temp_subdir("offset_empty");
        let opts = OffsetSearchOptions::default();
        let result = rebuild_with_offset_search(&bytes, &[], &profile(), &dir, &opts).unwrap();
        assert!(result.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_search_default_options_are_512_step_1() {
        let opts = OffsetSearchOptions::default();
        assert_eq!(opts.max_offset, 512);
        assert_eq!(opts.step, 1);
    }

    #[test]
    fn offset_search_multiple_candidates_each_get_inner_vec() {
        let jpeg0 = make_valid_jpeg(320, 240);
        let jpeg1 = make_valid_jpeg(640, 480);
        let mut bytes = jpeg0.clone();
        let off1 = bytes.len();
        bytes.extend_from_slice(&jpeg1);

        let candidates = vec![
            make_candidate(0, jpeg0.len(), false, false, Some(320), Some(240)),
            make_candidate(off1, off1 + jpeg1.len(), false, false, Some(640), Some(480)),
        ];
        let dir = temp_subdir("offset_multi");
        let opts = OffsetSearchOptions { max_offset: 0, step: 1 };
        let result = rebuild_with_offset_search(&bytes, &candidates, &profile(), &dir, &opts).unwrap();
        assert_eq!(result.len(), 2);
        // Each candidate with max_offset=0 should produce exactly one file.
        assert_eq!(result[0].len(), 1);
        assert_eq!(result[1].len(), 1);
        assert_eq!(result[0][0].file_name().unwrap(), "rebuilt_000_offset_0000.jpg");
        assert_eq!(result[1][0].file_name().unwrap(), "rebuilt_001_offset_0000.jpg");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
