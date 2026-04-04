use std::io::{self, Write};
use std::path::Path;

use crate::jpeg::candidate::RecoveryStatus;
use crate::jpeg::validate::ValidatedCandidate;
use crate::reconstruct::rebuilder::OffsetSearchResult;

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
    write_report_with_scoring(path, candidates, &[])
}

/// Write one JSONL line per candidate, with optional scoring details aligned by index.
pub fn write_report_with_scoring(
    path: &Path,
    candidates: &[ValidatedCandidate],
    scoring: &[Option<CandidateScoringInfo>],
) -> Result<(), ReportError> {
    let file = std::fs::File::create(path)?;
    let mut writer = io::BufWriter::new(file);
    for (index, candidate) in candidates.iter().enumerate() {
        let line = JsonlRecord::from_validated_with_scoring(candidate, scoring.get(index).and_then(|s| s.as_ref()))
            .to_json_line();
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
    pub scoring: Option<CandidateScoringInfo>,
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

#[derive(Debug, Clone, PartialEq)]
pub struct CandidateScoringInfo {
    pub selected_offset: usize,
    pub used_decode_score: bool,
    pub decode_success: Option<bool>,
    pub entropy_score: f32,
    pub decode_score: Option<f32>,
    pub colour_score: Option<f32>,
    pub pixel_entropy_score: Option<f32>,
    pub artifact_score: Option<f32>,
    pub final_score: f32,
}

impl JsonlRecord {
    pub fn from_validated(candidate: &ValidatedCandidate) -> Self {
        Self::from_validated_with_scoring(candidate, None)
    }

    pub fn from_validated_with_scoring(
        candidate: &ValidatedCandidate,
        scoring: Option<&CandidateScoringInfo>,
    ) -> Self {
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
            scoring: scoring.cloned(),
        }
    }

    pub fn to_json_line(&self) -> String {
        let status = match self.status {
            RecoveryStatus::Recovered => "recovered",
            RecoveryStatus::Truncated => "truncated",
        };
        let scoring = match &self.scoring {
            Some(scoring) => scoring.to_json_object(),
            None => "null".to_string(),
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
                "}},",
                "\"scoring\":{}",
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
            scoring,
        )
    }
}

impl CandidateScoringInfo {
    pub fn from_offset_search_result(result: &OffsetSearchResult) -> Self {
        let (decode_success, decode_score, colour_score, pixel_entropy_score, artifact_score) =
            match &result.decode_score {
                Some(decode) => (
                    Some(true),
                    Some(decode.total),
                    Some(decode.colour_balance),
                    Some(decode.pixel_entropy),
                    Some(decode.block_artifact_score),
                ),
                None => (None, None, None, None, None),
            };

        Self {
            selected_offset: result.offset,
            used_decode_score: result.used_decode_score,
            decode_success,
            entropy_score: result.score.total,
            decode_score,
            colour_score,
            pixel_entropy_score,
            artifact_score,
            final_score: result.final_score,
        }
    }

    fn to_json_object(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"selected_offset\":{},",
                "\"used_decode_score\":{},",
                "\"decode_success\":{},",
                "\"entropy_score\":{:.3},",
                "\"decode_score\":{},",
                "\"colour_score\":{},",
                "\"pixel_entropy_score\":{},",
                "\"artifact_score\":{},",
                "\"final_score\":{:.3}",
                "}}"
            ),
            self.selected_offset,
            self.used_decode_score,
            json_opt_bool(self.decode_success),
            self.entropy_score,
            json_opt_f32(self.decode_score),
            json_opt_f32(self.colour_score),
            json_opt_f32(self.pixel_entropy_score),
            json_opt_f32(self.artifact_score),
            self.final_score,
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

fn json_opt_f32(value: Option<f32>) -> String {
    match value {
        Some(v) => format!("{v:.3}"),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jpeg::candidate::RecoveryStatus;
    use crate::reconstruct::rebuilder::OffsetSearchResult;
    use crate::reconstruct::scorer::{DecodeAwareScore, JpegScore};

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

    fn sample_scoring() -> CandidateScoringInfo {
        CandidateScoringInfo {
            selected_offset: 12,
            used_decode_score: true,
            decode_success: Some(true),
            entropy_score: 0.742,
            decode_score: Some(0.891),
            colour_score: Some(0.850),
            pixel_entropy_score: Some(0.910),
            artifact_score: Some(0.120),
            final_score: 0.889,
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
        assert!(record.scoring.is_none());
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
        assert!(json.contains("\"scoring\":null"));
    }

    #[test]
    fn serializes_scoring_object_when_present() {
        let json = JsonlRecord::from_validated_with_scoring(&sample_candidate(), Some(&sample_scoring())).to_json_line();

        assert!(json.contains("\"scoring\":{"));
        assert!(json.contains("\"decode_success\":true"));
        assert!(json.contains("\"colour_score\":0.850"));
        assert!(json.contains("\"entropy_score\":0.742"));
        assert!(json.contains("\"artifact_score\":0.120"));
        assert!(json.contains("\"final_score\":0.889"));
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

    #[test]
    fn write_report_with_scoring_aligns_scores_by_index() {
        let candidates = vec![sample_candidate(), sample_candidate()];
        let scoring = vec![Some(sample_scoring()), None];
        let dir = std::env::temp_dir();
        let path = dir.join("carve_test_scored_report.jsonl");

        write_report_with_scoring(&path, &candidates, &scoring).expect("write_report_with_scoring should succeed");

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"scoring\":{"));
        assert!(lines[1].contains("\"scoring\":null"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn maps_offset_search_result_into_scoring_info() {
        let result = OffsetSearchResult {
            path: std::path::PathBuf::from("rebuilt_000_offset_0000.jpg"),
            offset: 0,
            score: JpegScore {
                byte_entropy: 0.8,
                unique_byte_ratio: 0.7,
                unexpected_markers: 0,
                total: 0.76,
            },
            decode_score: Some(DecodeAwareScore {
                decode_success_score: 1.0,
                colour_balance: 0.85,
                pixel_entropy: 0.91,
                block_artifact_score: 0.12,
                total: 0.89,
            }),
            final_score: 0.89,
            used_decode_score: true,
        };

        let scoring = CandidateScoringInfo::from_offset_search_result(&result);
        assert_eq!(scoring.selected_offset, 0);
        assert_eq!(scoring.decode_success, Some(true));
        assert_eq!(scoring.entropy_score, 0.76);
        assert_eq!(scoring.decode_score, Some(0.89));
        assert_eq!(scoring.colour_score, Some(0.85));
        assert_eq!(scoring.pixel_entropy_score, Some(0.91));
        assert_eq!(scoring.artifact_score, Some(0.12));
        assert_eq!(scoring.final_score, 0.89);
    }
}
