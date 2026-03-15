use super::camera_profile::CameraJpegProfile;

// JPEG marker bytes (second byte of FF XX pair)
const SOI: u8 = 0xD8;
const DQT: u8 = 0xDB;
const SOF0: u8 = 0xC0;
const DHT: u8 = 0xC4;
const DRI: u8 = 0xDD;
const SOS: u8 = 0xDA;

/// Write a JPEG marker + length-prefixed segment into `out`.
///
/// `marker` is the second byte of the `FF XX` pair.
/// `payload` is written verbatim after the 2-byte big-endian length field.
/// Length = 2 + payload.len() (per JPEG spec).
fn push_segment(out: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    out.push(0xFF);
    out.push(marker);
    let len = (2 + payload.len()) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
}

/// Build a complete JPEG header from a [`CameraJpegProfile`] with the given dimensions.
///
/// Emits segments in order: `SOI → DQT(s) → SOF0 → DHT(s) → DRI? → SOS`.
/// The returned bytes end immediately after the SOS segment (i.e. at the start
/// of the entropy stream) — no entropy data or EOI are included.
///
/// # Panics
///
/// Panics if `width == 0 || height == 0`, as zero-dimension JPEGs are invalid.
pub fn build_header(profile: &CameraJpegProfile, width: u16, height: u16) -> Vec<u8> {
    assert!(width > 0 && height > 0, "JPEG dimensions must be non-zero");

    let mut out = Vec::new();

    // SOI — no length field
    out.push(0xFF);
    out.push(SOI);

    // DQT segments
    for payload in &profile.dqt_segments {
        push_segment(&mut out, DQT, payload);
    }

    // SOF0 — inject width and height
    {
        let nf = profile.sof0_template.components.len() as u8;
        // SOF0 payload: precision(1) + height(2) + width(2) + Nf(1) + Nf×3 bytes
        let mut sof_payload = Vec::with_capacity(6 + 3 * nf as usize);
        sof_payload.push(profile.sof0_template.precision);
        sof_payload.extend_from_slice(&height.to_be_bytes());
        sof_payload.extend_from_slice(&width.to_be_bytes());
        sof_payload.push(nf);
        for comp in &profile.sof0_template.components {
            sof_payload.push(comp.id);
            sof_payload.push(comp.sampling.as_byte());
            sof_payload.push(comp.qt_selector);
        }
        push_segment(&mut out, SOF0, &sof_payload);
    }

    // DHT segments
    for payload in &profile.dht_segments {
        push_segment(&mut out, DHT, payload);
    }

    // DRI segment (optional)
    if let Some(interval) = profile.dri {
        push_segment(&mut out, DRI, &interval.to_be_bytes());
    }

    // SOS
    push_segment(&mut out, SOS, &profile.sos_segment);

    out
}

/// Find the last occurrence of a 2-byte window in a slice.
#[cfg(test)]
fn find_last(haystack: &[u8], needle: [u8; 2]) -> Option<usize> {
    haystack
        .windows(2)
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .last()
}

/// Find the first occurrence of a 2-byte window in a slice.
#[cfg(test)]
fn find_first(haystack: &[u8], needle: [u8; 2]) -> Option<usize> {
    haystack.windows(2).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconstruct::camera_profile::CameraJpegProfile;

    fn profile_no_dht() -> CameraJpegProfile {
        CameraJpegProfile::canon_ixus_310hs()
    }

    fn profile_with_dht() -> CameraJpegProfile {
        CameraJpegProfile::canon_ixus_310hs().with_dht(vec![vec![0x00u8; 1]])
    }

    #[test]
    fn header_starts_with_soi() {
        let hdr = build_header(&profile_no_dht(), 100, 100);
        assert_eq!(&hdr[..2], &[0xFF, 0xD8], "must begin with SOI");
    }

    #[test]
    fn header_ends_with_sos_segment() {
        let hdr = build_header(&profile_no_dht(), 100, 100);
        assert!(find_last(&hdr, [0xFF, 0xDA]).is_some(), "SOS marker FF DA must be present");
    }

    #[test]
    fn header_contains_dqt_marker() {
        let hdr = build_header(&profile_no_dht(), 100, 100);
        assert!(find_first(&hdr, [0xFF, 0xDB]).is_some(), "DQT marker FF DB must be present");
    }

    #[test]
    fn header_contains_sof0_marker() {
        let hdr = build_header(&profile_no_dht(), 640, 480);
        assert!(find_first(&hdr, [0xFF, 0xC0]).is_some(), "SOF0 marker FF C0 must be present");
    }

    #[test]
    fn sof0_dimensions_injected_correctly() {
        let width: u16 = 3264;
        let height: u16 = 2448;
        let hdr = build_header(&profile_no_dht(), width, height);

        // SOF0 byte layout (relative to FF C0 marker position):
        //   +0 +1 : FF C0 (marker)
        //   +2 +3 : length (big-endian, includes itself)
        //   +4    : precision
        //   +5 +6 : height
        //   +7 +8 : width
        let sof0_pos = find_first(&hdr, [0xFF, 0xC0]).expect("SOF0 not found");
        let h = u16::from_be_bytes([hdr[sof0_pos + 5], hdr[sof0_pos + 6]]);
        let w = u16::from_be_bytes([hdr[sof0_pos + 7], hdr[sof0_pos + 8]]);
        assert_eq!(h, height, "height mismatch in SOF0");
        assert_eq!(w, width, "width mismatch in SOF0");
    }

    #[test]
    fn width_height_injection_small_image() {
        let hdr = build_header(&profile_no_dht(), 1, 1);
        let sof0_pos = find_first(&hdr, [0xFF, 0xC0]).unwrap();
        let h = u16::from_be_bytes([hdr[sof0_pos + 5], hdr[sof0_pos + 6]]);
        let w = u16::from_be_bytes([hdr[sof0_pos + 7], hdr[sof0_pos + 8]]);
        assert_eq!(h, 1);
        assert_eq!(w, 1);
    }

    #[test]
    fn dht_segment_present_when_profile_has_dht() {
        let hdr = build_header(&profile_with_dht(), 100, 100);
        assert!(find_first(&hdr, [0xFF, 0xC4]).is_some(), "DHT marker FF C4 must be present");
    }

    #[test]
    fn no_dht_marker_when_profile_has_no_dht() {
        let hdr = build_header(&profile_no_dht(), 100, 100);
        assert!(find_first(&hdr, [0xFF, 0xC4]).is_none(), "DHT must be absent when profile has no DHT");
    }

    #[test]
    fn no_dri_segment_for_canon_ixus_310hs() {
        let hdr = build_header(&profile_no_dht(), 100, 100);
        assert!(find_first(&hdr, [0xFF, 0xDD]).is_none(), "DRI must be absent for Canon IXUS 310 HS");
    }

    #[test]
    fn segment_order_soi_dqt_sof0_sos() {
        let hdr = build_header(&profile_no_dht(), 640, 480);

        let soi  = find_first(&hdr, [0xFF, 0xD8]).unwrap();
        let dqt  = find_first(&hdr, [0xFF, 0xDB]).unwrap();
        let sof0 = find_first(&hdr, [0xFF, 0xC0]).unwrap();
        let sos  = find_last(&hdr,  [0xFF, 0xDA]).unwrap();

        assert!(soi  < dqt,  "SOI must precede DQT");
        assert!(dqt  < sof0, "DQT must precede SOF0");
        assert!(sof0 < sos,  "SOF0 must precede SOS");
    }

    #[test]
    fn output_is_concatenatable_with_entropy_and_eoi() {
        let hdr = build_header(&profile_no_dht(), 320, 240);
        let entropy = vec![0xABu8; 16];
        let eoi = [0xFF, 0xD9];

        let mut jpeg = hdr;
        jpeg.extend_from_slice(&entropy);
        jpeg.extend_from_slice(&eoi);

        assert_eq!(&jpeg[..2], &[0xFF, 0xD8]);
        assert_eq!(&jpeg[jpeg.len() - 2..], &[0xFF, 0xD9]);
    }

    #[test]
    fn dri_segment_emitted_when_profile_has_dri() {
        let mut profile = CameraJpegProfile::canon_ixus_310hs();
        profile.dri = Some(64);
        let hdr = build_header(&profile, 100, 100);

        let dri_pos = find_first(&hdr, [0xFF, 0xDD]).expect("DRI must be present");
        // DRI payload is always 2 bytes: the restart interval
        let p = dri_pos + 2; // skip FF DD
        let _len = u16::from_be_bytes([hdr[p], hdr[p + 1]]); // should be 4
        let interval = u16::from_be_bytes([hdr[p + 2], hdr[p + 3]]);
        assert_eq!(interval, 64);
    }
}
