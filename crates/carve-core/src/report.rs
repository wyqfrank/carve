use std::io::{self, Write};
use std::path::Path;

use crate::jpeg::candidate::RecoveryStatus;
use crate::jpeg::validate::ValidatedCandidate;

#[derive(Debug)]
pub struct ReportError(io::Error);

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "report error: {}", self.0)
    }
}

impl From<io::Error> for ReportError {
    fn from(e: io::Error) -> Self {
        Self(e)
    }
}

/// Write one JSONL line per candidate to `path`, in order.
pub fn write_report(path: &Path, candidates: &[ValidatedCandidate]) -> Result<(), ReportError> {
    let file = std::fs::File::create(path)?;
    let mut writer = io::BufWriter::new(file);
    for candidate in candidates {
        let line = JsonlRecord::from_validated(candidate).to_json_line();
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct JsonlRecord {
    pub start: usize,
    pub end: usize,
    pub status: RecoveryStatus,
    pub confidence: f32,
    pub jpeg_meta: JpegMeta,
    pub corruption: CorruptionInfo,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JpegMeta {
    pub width: Option<u16>,
    pub height: Option<u16>,
    pub is_progressive: Option<bool>,
    pub has_exif: bool,
    pub has_dqt: bool,
    pub has_dht: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptionInfo {
    pub truncated: bool,
    pub eoi_patched: bool,
    pub missing_soi: bool,
}

impl JsonlRecord {
    pub fn from_validated(candidate: &ValidatedCandidate) -> Self {
        let truncated = matches!(candidate.status, RecoveryStatus::Truncated);
        Self {
            start: candidate.start,
            end: candidate.end,
            status: candidate.status,
            confidence: candidate.confidence_score,
            jpeg_meta: JpegMeta {
                width: candidate.width,
                height: candidate.height,
                is_progressive: candidate.is_progressive,
                has_exif: candidate.has_exif,
                has_dqt: candidate.has_dqt,
                has_dht: candidate.has_dht,
            },
            corruption: CorruptionInfo {
                truncated,
                eoi_patched: candidate.patched_eoi,
                missing_soi: candidate.missing_soi,
            },
        }
    }

    pub fn to_json_line(&self) -> String {
        let status = match self.status {
            RecoveryStatus::Recovered => "recovered",
            RecoveryStatus::Truncated => "truncated",
        };
        format!(
            concat!(
                "{{",
                "\"start\":{},",
                "\"end\":{},",
                "\"status\":\"{}\",",
                "\"confidence\":{:.3},",
                "\"jpeg_meta\":{{",
                "\"width\":{},",
                "\"height\":{},",
                "\"is_progressive\":{},",
                "\"has_exif\":{},",
                "\"has_dqt\":{},",
                "\"has_dht\":{}",
                "}},",
                "\"corruption\":{{",
                "\"truncated\":{},",
                "\"eoi_patched\":{},",
                "\"missing_soi\":{}",
                "}}",
                "}}"
            ),
            self.start,
            self.end,
            status,
            self.confidence,
            json_opt_u16(self.jpeg_meta.width),
            json_opt_u16(self.jpeg_meta.height),
            json_opt_bool(self.jpeg_meta.is_progressive),
            self.jpeg_meta.has_exif,
            self.jpeg_meta.has_dqt,
            self.jpeg_meta.has_dht,
            self.corruption.truncated,
            self.corruption.eoi_patched,
            self.corruption.missing_soi,
        )
    }
}

fn json_opt_u16(value: Option<u16>) -> String {
    match value {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

fn json_opt_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jpeg::candidate::RecoveryStatus;

    fn sample_candidate() -> ValidatedCandidate {
        ValidatedCandidate {
            start: 128,
            end: 4096,
            status: RecoveryStatus::Truncated,
            patched_eoi: true,
            missing_soi: false,
            confidence_score: 0.75,
            has_exif: true,
            has_dqt: true,
            has_dht: false,
            width: Some(2992),
            height: Some(2992),
            is_progressive: Some(false),
            last_rst_marker: None,
        }
    }

    #[test]
    fn maps_validated_candidate_into_nested_schema() {
        let record = JsonlRecord::from_validated(&sample_candidate());
        assert_eq!(record.start, 128);
        assert_eq!(record.end, 4096);
        assert_eq!(record.status, RecoveryStatus::Truncated);
        assert_eq!(record.confidence, 0.75);
        assert_eq!(record.jpeg_meta.width, Some(2992));
        assert_eq!(record.jpeg_meta.height, Some(2992));
        assert_eq!(record.jpeg_meta.is_progressive, Some(false));
        assert!(record.corruption.truncated);
        assert!(record.corruption.eoi_patched);
    }

    #[test]
    fn serializes_json_with_jpeg_meta_and_corruption_objects() {
        let json = JsonlRecord::from_validated(&sample_candidate()).to_json_line();
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"jpeg_meta\":{"));
        assert!(json.contains("\"corruption\":{"));
        assert!(json.contains("\"confidence\":0.750"));
        assert!(json.contains("\"status\":\"truncated\""));
    }

    #[test]
    fn write_report_produces_one_line_per_candidate() {
        let candidates = vec![sample_candidate(), sample_candidate()];
        let dir = std::env::temp_dir();
        let path = dir.join("carve_test_report.jsonl");
        write_report(&path, &candidates).expect("write_report should succeed");
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert!(line.starts_with('{'));
            assert!(line.ends_with('}'));
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_report_empty_candidates_produces_empty_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("carve_test_empty_report.jsonl");
        write_report(&path, &[]).expect("write_report should succeed");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_report_lines_are_valid_json_objects() {
        let candidates = vec![sample_candidate()];
        let dir = std::env::temp_dir();
        let path = dir.join("carve_test_json_report.jsonl");
        write_report(&path, &candidates).expect("write_report should succeed");
        let contents = std::fs::read_to_string(&path).unwrap();
        let line = contents.lines().next().unwrap();
        assert!(line.contains("\"start\":128"));
        assert!(line.contains("\"end\":4096"));
        assert!(line.contains("\"jpeg_meta\":"));
        assert!(line.contains("\"corruption\":"));
        let _ = std::fs::remove_file(&path);
    }
}
