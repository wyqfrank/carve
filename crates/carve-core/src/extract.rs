use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::jpeg::validate::ValidatedCandidate;

const SOI_MARKER: [u8; 2] = [0xFF, 0xD8];
const EOI_MARKER: [u8; 2] = [0xFF, 0xD9];

#[derive(Debug)]
pub struct ExtractError(io::Error);

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "extract error: {}", self.0)
    }
}

impl From<io::Error> for ExtractError {
    fn from(e: io::Error) -> Self {
        Self(e)
    }
}

/// Extract each candidate as a `.jpg` file into `output_dir`.
///
/// Files are named `recovered_000.jpg`, `recovered_001.jpg`, … in candidate order.
/// When `candidate.patched_eoi` is true, `FF D9` is appended after the sliced bytes.
///
/// Returns the list of written paths in order.
pub fn extract_candidates(
    bytes: &[u8],
    candidates: &[ValidatedCandidate],
    output_dir: &Path,
) -> Result<Vec<PathBuf>, ExtractError> {
    let mut paths = Vec::with_capacity(candidates.len());
    for (i, candidate) in candidates.iter().enumerate() {
        let filename = format!("recovered_{:03}.jpg", i);
        let path = output_dir.join(&filename);
        let file = std::fs::File::create(&path)?;
        let mut writer = io::BufWriter::new(file);
        if candidate.missing_soi {
            writer.write_all(&SOI_MARKER)?;
        }
        let slice = &bytes[candidate.start..candidate.end];
        writer.write_all(slice)?;
        if candidate.patched_eoi {
            writer.write_all(&EOI_MARKER)?;
        }
        writer.flush()?;
        paths.push(path);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jpeg::candidate::RecoveryStatus;
    use crate::jpeg::validate::ValidatedCandidate;

    fn make_candidate(start: usize, end: usize, patched_eoi: bool) -> ValidatedCandidate {
        ValidatedCandidate {
            start,
            end,
            status: if patched_eoi {
                RecoveryStatus::Truncated
            } else {
                RecoveryStatus::Recovered
            },
            patched_eoi,
            missing_soi: false,
            confidence_score: 0.9,
            has_exif: false,
            has_dqt: true,
            has_dht: false,
            width: Some(320),
            height: Some(240),
            is_progressive: Some(false),
            last_rst_marker: None,
        }
    }

    fn temp_subdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("carve_extract_test_{}", name));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn extracts_slice_to_file() {
        let data: Vec<u8> = (0u8..=255).collect();
        let candidate = make_candidate(10, 20, false);
        let dir = temp_subdir("extracts_slice");
        let paths = extract_candidates(&data, &[candidate], &dir).unwrap();
        assert_eq!(paths.len(), 1);
        let written = std::fs::read(&paths[0]).unwrap();
        assert_eq!(written, &data[10..20]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appends_eoi_when_patched() {
        let data: Vec<u8> = (0u8..=255).collect();
        let candidate = make_candidate(0, 10, true);
        let dir = temp_subdir("appends_eoi");
        let paths = extract_candidates(&data, &[candidate], &dir).unwrap();
        let written = std::fs::read(&paths[0]).unwrap();
        assert_eq!(&written[..10], &data[0..10]);
        assert_eq!(&written[10..], &[0xFF, 0xD9]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_eoi_appended_when_not_patched() {
        let data: Vec<u8> = vec![0xAB; 16];
        let candidate = make_candidate(0, 16, false);
        let dir = temp_subdir("no_eoi");
        let paths = extract_candidates(&data, &[candidate], &dir).unwrap();
        let written = std::fs::read(&paths[0]).unwrap();
        assert_eq!(written.len(), 16);
        assert_eq!(written, data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_naming_is_deterministic() {
        let data = vec![0u8; 64];
        let candidates = vec![
            make_candidate(0, 10, false),
            make_candidate(10, 20, false),
            make_candidate(20, 30, false),
        ];
        let dir = temp_subdir("naming");
        let paths = extract_candidates(&data, &candidates, &dir).unwrap();
        assert!(paths[0].file_name().unwrap() == "recovered_000.jpg");
        assert!(paths[1].file_name().unwrap() == "recovered_001.jpg");
        assert!(paths[2].file_name().unwrap() == "recovered_002.jpg");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_candidates_returns_empty_vec() {
        let data = vec![0u8; 16];
        let dir = temp_subdir("empty");
        let paths = extract_candidates(&data, &[], &dir).unwrap();
        assert!(paths.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepends_soi_when_missing_soi_true() {
        let data: Vec<u8> = (0u8..=255).collect();
        let mut candidate = make_candidate(10, 20, false);
        candidate.missing_soi = true;
        let dir = temp_subdir("prepend_soi");
        let paths = extract_candidates(&data, &[candidate], &dir).unwrap();
        let written = std::fs::read(&paths[0]).unwrap();
        // Should start with FF D8 (SOI), then the original bytes
        assert_eq!(&written[..2], &[0xFF, 0xD8]);
        assert_eq!(&written[2..], &data[10..20]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_soi_prepended_when_missing_soi_false() {
        let data: Vec<u8> = (0u8..=255).collect();
        let candidate = make_candidate(10, 20, false);
        let dir = temp_subdir("no_prepend_soi");
        let paths = extract_candidates(&data, &[candidate], &dir).unwrap();
        let written = std::fs::read(&paths[0]).unwrap();
        assert_eq!(written, &data[10..20]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
