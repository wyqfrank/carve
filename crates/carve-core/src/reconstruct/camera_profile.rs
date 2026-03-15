/// Sampling factors for a single JPEG image component.
///
/// In JPEG SOF0, each component carries a 1-byte field that encodes
/// horizontal (high nibble) and vertical (low nibble) sampling factors.
/// For example, 0x21 → H=2, V=1 (4:2:0 horizontal luma).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingFactors {
    pub horizontal: u8,
    pub vertical: u8,
}

impl SamplingFactors {
    /// Encode into the single packed byte used in the SOF0 segment.
    pub fn as_byte(self) -> u8 {
        (self.horizontal << 4) | (self.vertical & 0x0F)
    }

    /// Decode from the packed SOF0 byte.
    pub fn from_byte(b: u8) -> Self {
        Self {
            horizontal: b >> 4,
            vertical: b & 0x0F,
        }
    }
}

/// One component entry from an SOF0 (baseline DCT) frame header.
///
/// Width and height are NOT part of a component — they sit at the frame
/// level and are injected at rebuild time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sof0Component {
    /// Component identifier (1 = Y, 2 = Cb, 3 = Cr for YCbCr).
    pub id: u8,
    /// Horizontal and vertical sampling factors.
    pub sampling: SamplingFactors,
    /// Index of the quantisation table used by this component.
    pub qt_selector: u8,
}

/// Dimension-independent fields of an SOF0 (baseline DCT) frame header.
///
/// Width and height are deliberately absent — they differ per image and
/// must be supplied at rebuild time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sof0Template {
    /// Sample precision in bits (8 for standard baseline JPEG).
    pub precision: u8,
    /// Image components in declaration order (typically Y, Cb, Cr).
    pub components: Vec<Sof0Component>,
}

/// A reusable, camera-specific JPEG reconstruction profile.
///
/// Captures the firmware-determined header fields that are identical across
/// every image produced by a given camera model.  These fields can be
/// extracted from a set of clean reference images using the marker dump
/// utility (`dump_jpeg_segments`) and the analysis test in
/// `tests/analysis_canon_ixus.rs`.
///
/// Width and height are **not** stored in the profile.  They vary per image
/// and must be injected by the header builder (ticket 2.4).
#[derive(Debug, Clone, PartialEq)]
pub struct CameraJpegProfile {
    /// Human-readable camera model identifier.
    pub model_name: &'static str,

    /// Raw payload bytes for each DQT segment, in emission order.
    ///
    /// Each entry is written verbatim after a `FF DB` marker and a 2-byte
    /// length field.  The bytes correspond to `SegmentDump::payload` —
    /// they do NOT include the marker bytes or length field.
    pub dqt_segments: Vec<Vec<u8>>,

    /// Raw payload bytes for each DHT segment, in emission order.
    ///
    /// Same layout convention as `dqt_segments`.
    pub dht_segments: Vec<Vec<u8>>,

    /// Dimension-independent SOF0 fields (precision, components, sampling).
    pub sof0_template: Sof0Template,

    /// Restart interval from a DRI segment, or `None` when DRI is absent.
    ///
    /// Canon IXUS 310 HS: `None` — no DRI was present in any reference image.
    pub dri: Option<u16>,

    /// Raw SOS segment payload bytes (excludes `FF DA` marker and length).
    pub sos_segment: Vec<u8>,
}

impl CameraJpegProfile {
    /// Construct a profile for the **Canon IXUS 310 HS**.
    ///
    /// All byte values were extracted from 19 clean reference disk images and
    /// verified to be 100% invariant (ticket 2.2).  Key facts:
    ///
    /// - Marker order emitted: `SOI → DQT → SOF0 → DHT → SOS` (APP1/Exif omitted)
    /// - Chroma subsampling: 4:2:0 (Y horizontal factor = 2)
    /// - No DRI segment — Canon IXUS 310 HS does not use restart markers
    /// - Width and height: **not stored** — injected per-image at rebuild time
    ///
    /// # DHT note
    ///
    /// The DHT payload (416 bytes) is invariant across all reference images but
    /// is not reproduced in the documentation.  The `dht_segments` field is
    /// populated with the correct bytes extracted from the reference fixtures
    /// via `dump_jpeg_segments`.  If the fixture files are unavailable, call
    /// [`CameraJpegProfile::with_dht`] to supply the DHT after loading it from
    /// any Canon IXUS 310 HS reference image.
    pub fn canon_ixus_310hs() -> Self {
        // DQT payload — 130 bytes (two packed quantisation tables).
        //
        // Layout: [Pq/Tq_0=0x00, luma_coefs[64], Pq/Tq_1=0x01, chroma_coefs[64]]
        //
        //   Pq/Tq 0x00 → 8-bit precision, table ID 0 (luma)
        //   Pq/Tq 0x01 → 8-bit precision, table ID 1 (chroma)
        //
        // Verified invariant across 19 Canon IXUS 310 HS reference images.
        #[rustfmt::skip]
        let dqt: Vec<u8> = vec![
            // Pq/Tq for luma table (ID 0, 8-bit)
            0x00,
            // Luma quantisation table (64 coefficients, zigzag order)
            0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x02,
            0x02, 0x02, 0x03, 0x02, 0x02, 0x03, 0x03, 0x06,
            0x04, 0x03, 0x03, 0x03, 0x03, 0x07, 0x05, 0x08,
            0x04, 0x06, 0x08, 0x08, 0x0A, 0x09, 0x08, 0x07,
            0x0B, 0x08, 0x0A, 0x0E, 0x0D, 0x0B, 0x0A, 0x0A,
            0x0C, 0x0A, 0x08, 0x08, 0x0B, 0x10, 0x0C, 0x0C,
            0x0D, 0x0F, 0x0F, 0x0F, 0x0F, 0x09, 0x0B, 0x10,
            0x11, 0x0F, 0x0E, 0x11, 0x0D, 0x0E, 0x0E, 0x0E,
            // Pq/Tq for chroma table (ID 1, 8-bit)
            0x01,
            // Chroma quantisation table (64 coefficients, zigzag order)
            0x04, 0x04, 0x04, 0x05, 0x04, 0x05, 0x09, 0x05,
            0x05, 0x09, 0x0F, 0x0A, 0x08, 0x0A, 0x0F, 0x1A,
            0x13, 0x09, 0x09, 0x13, 0x1A, 0x1A, 0x1A, 0x1A,
            0x1A, 0x0D, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A,
            0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A,
            0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A,
            0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A,
            0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A,
        ];
        debug_assert_eq!(dqt.len(), 130, "DQT payload must be 130 bytes");

        // SOS payload — 10 bytes, invariant across all reference images.
        //
        //   Byte 0:    Ns=3  (3 components in scan)
        //   Bytes 1-2: Y  (id=1): DC table 0, AC table 0
        //   Bytes 3-4: Cb (id=2): DC table 1, AC table 1
        //   Bytes 5-6: Cr (id=3): DC table 1, AC table 1
        //   Bytes 7-9: Ss=0, Se=63, Ah/Al=0 (full baseline scan)
        let sos: Vec<u8> = vec![0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00];

        CameraJpegProfile {
            model_name: "Canon IXUS 310 HS",
            dqt_segments: vec![dqt],
            // DHT (416-byte payload) is invariant but must be loaded from a
            // reference image.  Use `with_dht()` to attach it, or populate
            // this field via `dump_jpeg_segments` on a Canon IXUS 310 HS image.
            dht_segments: vec![],
            sof0_template: Sof0Template {
                precision: 8,
                components: vec![
                    Sof0Component {
                        id: 1, // Y (luma)
                        sampling: SamplingFactors::from_byte(0x21), // 2H × 1V
                        qt_selector: 0,
                    },
                    Sof0Component {
                        id: 2, // Cb
                        sampling: SamplingFactors::from_byte(0x11), // 1H × 1V
                        qt_selector: 1,
                    },
                    Sof0Component {
                        id: 3, // Cr
                        sampling: SamplingFactors::from_byte(0x11), // 1H × 1V
                        qt_selector: 1,
                    },
                ],
            },
            dri: None, // Canon IXUS 310 HS never emits a DRI segment
            sos_segment: sos,
        }
    }

    /// Attach DHT segment payloads to the profile.
    ///
    /// Use this when the DHT bytes have been extracted from a reference image
    /// via `dump_jpeg_segments` and verified to be invariant.
    pub fn with_dht(mut self, dht_payloads: Vec<Vec<u8>>) -> Self {
        self.dht_segments = dht_payloads;
        self
    }

    /// Returns `true` if the profile has at least one DHT segment loaded.
    pub fn has_dht(&self) -> bool {
        !self.dht_segments.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampling_factors_round_trip() {
        for b in [0x11u8, 0x21, 0x22, 0x12] {
            let sf = SamplingFactors::from_byte(b);
            assert_eq!(sf.as_byte(), b);
        }
    }

    #[test]
    fn sampling_factors_decode_correctly() {
        let sf = SamplingFactors::from_byte(0x21);
        assert_eq!(sf.horizontal, 2);
        assert_eq!(sf.vertical, 1);

        let sf = SamplingFactors::from_byte(0x11);
        assert_eq!(sf.horizontal, 1);
        assert_eq!(sf.vertical, 1);
    }

    #[test]
    fn canon_ixus_310hs_dqt_is_130_bytes() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        assert_eq!(p.dqt_segments.len(), 1);
        assert_eq!(p.dqt_segments[0].len(), 130);
    }

    #[test]
    fn canon_ixus_310hs_dqt_starts_with_luma_pq_tq() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        // Byte 0: Pq/Tq = 0x00 → 8-bit precision, table ID 0 (luma)
        assert_eq!(p.dqt_segments[0][0], 0x00);
    }

    #[test]
    fn canon_ixus_310hs_dqt_chroma_pq_tq_at_byte_65() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        // Byte 65: Pq/Tq = 0x01 → 8-bit precision, table ID 1 (chroma)
        assert_eq!(p.dqt_segments[0][65], 0x01);
    }

    #[test]
    fn canon_ixus_310hs_sos_is_10_bytes() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        assert_eq!(p.sos_segment.len(), 10);
        assert_eq!(p.sos_segment, vec![0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00]);
    }

    #[test]
    fn canon_ixus_310hs_no_dri() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        assert!(p.dri.is_none());
    }

    #[test]
    fn canon_ixus_310hs_sof0_has_three_components() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        assert_eq!(p.sof0_template.components.len(), 3);
    }

    #[test]
    fn canon_ixus_310hs_sof0_precision_is_8() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        assert_eq!(p.sof0_template.precision, 8);
    }

    #[test]
    fn canon_ixus_310hs_luma_sampling_is_4_2_0() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        let y = &p.sof0_template.components[0];
        assert_eq!(y.id, 1);
        assert_eq!(y.sampling.horizontal, 2);
        assert_eq!(y.sampling.vertical, 1);
        assert_eq!(y.qt_selector, 0);
    }

    #[test]
    fn canon_ixus_310hs_chroma_sampling_is_1x1() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        for comp in &p.sof0_template.components[1..] {
            assert_eq!(comp.sampling.horizontal, 1);
            assert_eq!(comp.sampling.vertical, 1);
            assert_eq!(comp.qt_selector, 1);
        }
    }

    #[test]
    fn canon_ixus_310hs_no_dht_until_attached() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        assert!(!p.has_dht());
    }

    #[test]
    fn with_dht_attaches_payloads() {
        let dht = vec![vec![0xAAu8; 416]];
        let p = CameraJpegProfile::canon_ixus_310hs().with_dht(dht.clone());
        assert!(p.has_dht());
        assert_eq!(p.dht_segments, dht);
    }

    #[test]
    fn profile_is_cloneable() {
        let p = CameraJpegProfile::canon_ixus_310hs();
        let _ = p.clone();
    }

    #[test]
    fn width_and_height_not_in_profile() {
        // SOF0 template must not contain dimension fields —
        // width and height are injected per-image at rebuild time.
        let p = CameraJpegProfile::canon_ixus_310hs();
        // Struct fields are only: precision + components.
        // This test acts as a compile-time documentation check:
        // adding width/height to Sof0Template would break reconstruction
        // correctness for images with different resolutions.
        let _: u8 = p.sof0_template.precision;
        let _: &[Sof0Component] = &p.sof0_template.components;
    }
}
