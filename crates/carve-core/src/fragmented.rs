// Multi-fragment (non-contiguous) JPEG recovery — smart carving
//
// Divides a disk image into fixed-size clusters, finds JPEG candidates that
// are truncated at cluster boundaries, and attempts to reassemble them by
// searching for continuation clusters.  RST marker sequencing provides a
// fast-path filter: if the last RST seen before truncation was RST-N, only
// clusters that contain FF D(N+1) within a short window near the start are
// tried first.

use crate::jpeg::entropy::next_rst;
use crate::jpeg::candidate::RecoveryStatus;
use crate::jpeg::validate::{validate_candidate, ValidatedCandidate, ValidationOptions, PatchEoiPolicy};
use crate::scanner::recover_candidates;

/// How far into a candidate continuation cluster to search for the expected
/// RST marker when applying the fast-path filter.
const RST_SEARCH_WINDOW: usize = 64;

/// A JPEG candidate assembled from two or more non-contiguous disk clusters.
#[derive(Debug)]
pub struct MultiFragmentCandidate {
    /// The reassembled JPEG bytes, suitable for extraction or further processing.
    pub data: Vec<u8>,
    /// Byte offsets within the original disk image for each fragment used.
    ///
    /// `fragment_offsets[0]` is the start of the first (header) fragment;
    /// `fragment_offsets[1]` is the start of the continuation cluster.
    pub fragment_offsets: Vec<usize>,
    /// Validated metadata for the assembled image.  `start` and `end` are
    /// offsets within `data`, not within the original disk image.
    pub validated: ValidatedCandidate,
    /// Whether RST marker sequencing was used to locate the continuation
    /// cluster (true = high-confidence seam; false = exhaustive search).
    pub rst_aligned: bool,
}

/// Scan a disk image for fragmented JPEG candidates.
///
/// The image is divided into `cluster_size`-byte clusters (the last cluster
/// may be shorter).  For each cluster a bounded scan finds JPEG candidates
/// whose entropy stream reaches the cluster boundary without finding EOI
/// (i.e., they are truncated at a cluster edge).  Every such candidate
/// triggers a search over the remaining clusters for a plausible continuation:
///
/// 1. **RST fast filter** — if the truncated stream ended on RST-N, only
///    clusters that contain `FF D(N+1)` within the first [`RST_SEARCH_WINDOW`]
///    bytes are tried.
/// 2. **Assembly & re-validation** — the JPEG bytes from the header to the end
///    of its source cluster are concatenated with the candidate continuation
///    cluster and re-validated.  If EOI is found the result is emitted as a
///    [`MultiFragmentCandidate`].
///
/// Returns an empty `Vec` when `cluster_size` is zero, when the image fits in
/// a single cluster, or when no valid assembly is found.
pub fn recover_fragmented_candidates(
    bytes: &[u8],
    cluster_size: usize,
    val_options: ValidationOptions,
) -> Vec<MultiFragmentCandidate> {
    if cluster_size == 0 || bytes.len() <= cluster_size {
        return Vec::new();
    }

    let num_clusters = bytes.len().div_ceil(cluster_size);
    let mut results: Vec<MultiFragmentCandidate> = Vec::new();

    // Options used when scanning individual clusters: always allow truncated
    // results so we can detect candidates that run off the cluster boundary.
    let cluster_options = ValidationOptions {
        max_size: cluster_size,
        allow_truncated: true,
        patch_eoi: PatchEoiPolicy::None,
    };

    // Collect (source_cluster_idx, candidate) for every JPEG that is truncated
    // exactly at its cluster boundary (entropy hit OutOfBounds at cluster end).
    let mut truncated_at_boundary: Vec<(usize, ValidatedCandidate)> = Vec::new();

    for cluster_idx in 0..num_clusters {
        let cluster_start = cluster_idx * cluster_size;
        let cluster_end = (cluster_start + cluster_size).min(bytes.len());
        let cluster_bytes = &bytes[cluster_start..cluster_end];
        let cluster_len = cluster_bytes.len();

        for mut c in recover_candidates(cluster_bytes, cluster_options) {
            if c.status != RecoveryStatus::Truncated {
                continue;
            }
            // Only pursue candidates whose entropy reached the cluster boundary
            // (end == cluster_len).  Candidates truncated by an unexpected
            // marker in the middle of a cluster are skipped.
            if c.end < cluster_len {
                continue;
            }
            // Adjust offsets to be absolute within `bytes`.
            c.start += cluster_start;
            c.end += cluster_start;
            truncated_at_boundary.push((cluster_idx, c));
        }
    }

    // For each truncated candidate, search other clusters for a valid continuation.
    for (src_idx, truncated) in &truncated_at_boundary {
        let jpeg_start = truncated.start; // absolute start of this JPEG
        let src_cluster_end = (src_idx + 1) * cluster_size;
        let src_cluster_end = src_cluster_end.min(bytes.len());
        let first_frag = &bytes[jpeg_start..src_cluster_end];

        let expected_rst = truncated.last_rst_marker.map(next_rst);

        'next_cluster: for next_idx in 0..num_clusters {
            if next_idx == *src_idx {
                continue;
            }

            let next_start = next_idx * cluster_size;
            let next_end = (next_start + cluster_size).min(bytes.len());
            let next_cluster = &bytes[next_start..next_end];

            // RST fast filter: if the stream ended on RST-N, only consider
            // clusters that contain FF D(N+1) near their start.
            if let Some(expected) = expected_rst {
                if !cluster_has_rst_near_start(next_cluster, expected) {
                    continue 'next_cluster;
                }
            }

            // Assemble and re-validate.
            let mut assembled = Vec::with_capacity(first_frag.len() + next_cluster.len());
            assembled.extend_from_slice(first_frag);
            assembled.extend_from_slice(next_cluster);

            let assembled_options = ValidationOptions {
                max_size: assembled.len(),
                allow_truncated: false,
                patch_eoi: val_options.patch_eoi,
            };

            if let Some(validated) = validate_candidate(&assembled, 0, assembled_options) {
                if validated.status == RecoveryStatus::Recovered {
                    results.push(MultiFragmentCandidate {
                        data: assembled,
                        fragment_offsets: vec![jpeg_start, next_start],
                        validated,
                        rst_aligned: expected_rst.is_some(),
                    });
                    break 'next_cluster;
                }
            }
        }
    }

    results
}

/// Return `true` if `cluster` contains `FF expected_rst` within the first
/// [`RST_SEARCH_WINDOW`] bytes.
fn cluster_has_rst_near_start(cluster: &[u8], expected_rst: u8) -> bool {
    let window = cluster.len().min(RST_SEARCH_WINDOW);
    if window < 2 {
        return false;
    }
    for i in 0..window - 1 {
        if cluster[i] == 0xFF && cluster[i + 1] == expected_rst {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jpeg::markers;

    // ---------------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------------

    fn make_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        let mut v = vec![0xFF, marker, (len >> 8) as u8, len as u8];
        v.extend_from_slice(payload);
        v
    }

    /// Build a minimal valid JPEG header (SOI + DQT + SOF0 + SOS) and return
    /// the bytes up to and including the SOS segment payload.  Entropy data
    /// is NOT included so that callers can append their own.
    fn make_jpeg_header() -> Vec<u8> {
        let mut buf = vec![0xFF, markers::SOI];
        let mut dqt = vec![0x00u8];
        dqt.extend_from_slice(&[16u8; 64]);
        buf.extend(make_segment(markers::DQT, &dqt));
        let sof = [
            0x08, 0x00, 0xF0, 0x01, 0x40, 0x03, // precision, height=240, width=320
            0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
        ];
        buf.extend(make_segment(markers::SOF0, &sof));
        let sos = [0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00];
        buf.extend(make_segment(markers::SOS, &sos));
        buf
    }

    fn default_options(max_size: usize) -> ValidationOptions {
        ValidationOptions {
            allow_truncated: false,
            max_size,
            patch_eoi: PatchEoiPolicy::None,
        }
    }

    // ---------------------------------------------------------------------------
    // cluster_has_rst_near_start
    // ---------------------------------------------------------------------------

    #[test]
    fn rst_filter_finds_pattern_at_start() {
        let cluster = [0xFF, 0xD4, 0x00, 0x00]; // RST4 at byte 0
        assert!(cluster_has_rst_near_start(&cluster, 0xD4));
    }

    #[test]
    fn rst_filter_finds_pattern_within_window() {
        let mut cluster = vec![0xAAu8; 20];
        cluster[18] = 0xFF;
        cluster[19] = 0xD5; // RST5 within window
        assert!(cluster_has_rst_near_start(&cluster, 0xD5));
    }

    #[test]
    fn rst_filter_rejects_pattern_beyond_window() {
        let mut cluster = vec![0xAAu8; RST_SEARCH_WINDOW + 10];
        cluster[RST_SEARCH_WINDOW + 2] = 0xFF;
        cluster[RST_SEARCH_WINDOW + 3] = 0xD3; // RST3 beyond window
        assert!(!cluster_has_rst_near_start(&cluster, 0xD3));
    }

    #[test]
    fn rst_filter_rejects_wrong_rst_value() {
        let cluster = [0xFF, 0xD3]; // RST3, not RST4
        assert!(!cluster_has_rst_near_start(&cluster, 0xD4));
    }

    #[test]
    fn rst_filter_empty_cluster_returns_false() {
        assert!(!cluster_has_rst_near_start(&[], 0xD0));
    }

    // ---------------------------------------------------------------------------
    // recover_fragmented_candidates — edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn zero_cluster_size_returns_empty() {
        let data = vec![0xAAu8; 100];
        let result = recover_fragmented_candidates(&data, 0, default_options(data.len()));
        assert!(result.is_empty());
    }

    #[test]
    fn single_cluster_returns_empty() {
        let mut data = make_jpeg_header();
        data.extend_from_slice(&[0xAB, 0xCD, 0xFF, 0xD9]);
        // cluster_size >= data.len() → single cluster, nothing to search
        let result = recover_fragmented_candidates(&data, data.len() + 100, default_options(data.len()));
        assert!(result.is_empty());
    }

    #[test]
    fn noise_only_returns_empty() {
        let data = vec![0xAAu8; 512];
        let result = recover_fragmented_candidates(&data, 256, default_options(data.len()));
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // recover_fragmented_candidates — two-fragment assembly without RST markers
    // ---------------------------------------------------------------------------

    /// Inject garbage between the entropy halves of a JPEG (no RST markers).
    /// The engine should discard the garbage cluster and assemble the two
    /// real fragments into a recovered candidate.
    #[test]
    fn reassembles_jpeg_split_across_non_contiguous_clusters_no_rst() {
        let header = make_jpeg_header();
        let entropy_part1: &[u8] = &[0xAB, 0xCD, 0xEF]; // no RST, no EOI
        let entropy_part2: &[u8] = &[0x12, 0x34, 0xFF, 0xD9]; // continuation + EOI

        // Cluster size must be large enough to hold the header + first entropy chunk.
        let cluster_size = 512;
        assert!(header.len() + entropy_part1.len() < cluster_size);

        // Cluster 0: JPEG header + first entropy chunk, zero-padded to cluster_size.
        let mut cluster0 = header.clone();
        cluster0.extend_from_slice(entropy_part1);
        cluster0.resize(cluster_size, 0x00);

        // Cluster 1: pure garbage — no FF D9 anywhere.
        let cluster1 = vec![0xAAu8; cluster_size];

        // Cluster 2: second entropy chunk + EOI, zero-padded.
        let mut cluster2 = entropy_part2.to_vec();
        cluster2.resize(cluster_size, 0x00);

        let mut disk = cluster0.clone();
        disk.extend_from_slice(&cluster1);
        disk.extend_from_slice(&cluster2);

        let results = recover_fragmented_candidates(&disk, cluster_size, default_options(disk.len()));

        assert_eq!(results.len(), 1, "expected exactly one recovered candidate");
        let mfc = &results[0];
        assert_eq!(mfc.validated.status, RecoveryStatus::Recovered);
        assert!(!mfc.rst_aligned, "no RST markers → rst_aligned should be false");
        // Fragment offsets: start of JPEG (0) and start of cluster 2.
        assert_eq!(mfc.fragment_offsets[0], 0);
        assert_eq!(mfc.fragment_offsets[1], 2 * cluster_size);
    }

    // ---------------------------------------------------------------------------
    // recover_fragmented_candidates — RST-filtered two-fragment assembly
    // ---------------------------------------------------------------------------

    /// Build a disk image where cluster 0 contains the JPEG header + entropy
    /// ending on RST3, cluster 1 is garbage with no RST4 near the start, and
    /// cluster 2 starts with RST4 followed by the rest of the entropy + EOI.
    /// The RST fast filter should exclude cluster 1 and accept cluster 2.
    #[test]
    fn reassembles_jpeg_with_rst_filter_excluding_garbage_cluster() {
        let header = make_jpeg_header();
        let entropy_part1: &[u8] = &[0xAB, 0xCD, 0xFF, 0xD3]; // ends with RST3
        let entropy_part2: &[u8] = &[0xFF, 0xD4, 0x12, 0x34, 0xFF, 0xD9]; // RST4 + data + EOI

        let cluster_size = 512;
        assert!(header.len() + entropy_part1.len() < cluster_size);

        let mut cluster0 = header.clone();
        cluster0.extend_from_slice(entropy_part1);
        cluster0.resize(cluster_size, 0x00);

        // Cluster 1: garbage — ensure no FF D4 (RST4) in the first RST_SEARCH_WINDOW bytes.
        let cluster1 = vec![0xBBu8; cluster_size];

        // Cluster 2: starts immediately with RST4 sequence.
        let mut cluster2 = entropy_part2.to_vec();
        cluster2.resize(cluster_size, 0x00);

        let mut disk = cluster0.clone();
        disk.extend_from_slice(&cluster1);
        disk.extend_from_slice(&cluster2);

        let results = recover_fragmented_candidates(&disk, cluster_size, default_options(disk.len()));

        assert_eq!(results.len(), 1, "expected exactly one recovered candidate");
        let mfc = &results[0];
        assert_eq!(mfc.validated.status, RecoveryStatus::Recovered);
        assert!(mfc.rst_aligned, "RST3→RST4 filter was used → rst_aligned should be true");
        assert_eq!(mfc.fragment_offsets[0], 0);
        assert_eq!(mfc.fragment_offsets[1], 2 * cluster_size);
    }

    // ---------------------------------------------------------------------------
    // recovered candidate data is self-consistent
    // ---------------------------------------------------------------------------

    #[test]
    fn assembled_data_starts_with_soi() {
        let header = make_jpeg_header();
        let entropy_part1: &[u8] = &[0x11, 0x22];
        let entropy_part2: &[u8] = &[0x33, 0xFF, 0xD9];
        let cluster_size = 512;

        let mut cluster0 = header.clone();
        cluster0.extend_from_slice(entropy_part1);
        cluster0.resize(cluster_size, 0x00);

        let mut cluster1 = entropy_part2.to_vec();
        cluster1.resize(cluster_size, 0x00);

        let mut disk = cluster0;
        disk.extend_from_slice(&cluster1);

        let results = recover_fragmented_candidates(&disk, cluster_size, default_options(disk.len()));
        assert_eq!(results.len(), 1);
        // Assembled data must begin with SOI (FF D8).
        assert_eq!(&results[0].data[..2], &[0xFF, markers::SOI]);
    }
}
