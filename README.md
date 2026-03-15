# Carve

A digital forensics tool written in Rust that recovers corrupted JPEG images from raw byte streams. Unlike generic file carvers that rely solely on header detection, Carve performs entropy-aware JPEG scanning and camera-specific header reconstruction to improve recovery quality.

---

## The Problem

When a camera's SD card is corrupted, interrupted, or partially overwritten, the filesystem metadata is lost — but the raw image data often survives on the storage medium. Standard recovery tools find JPEGs by looking for `FF D8` (SOI) markers and copying bytes until `FF D9` (EOI). This works for simple cases but fails for:

- **Truncated files** — the EOI marker was never written
- **Colour-shifted images** — the carved entropy stream was paired with the wrong header, breaking the quantisation and Huffman tables
- **Block-shifted images** — carving started mid-MCU, causing the decoder to misalign its 8×8 pixel blocks
- **Entropy corruption** — byte stuffing violations or unexpected markers mid-stream

Carve addresses each of these specifically.

---

## How JPEG Recovery Works

A JPEG file has two distinct regions:

```
SOI → APP segments → DQT → SOF → DHT → SOS → [entropy stream] → EOI
```

- **Header** (SOI through SOS): structured, parseable, contains compression parameters
- **Entropy stream**: raw DCT-coded pixel data, mostly opaque binary

The header defines the quantisation tables (DQT) and Huffman tables (DHT) used to decode the entropy stream. If a carved image uses the wrong tables — even slightly — the result is severe colour distortion or a decode failure.

Additionally, the entropy stream uses **byte stuffing**: any `FF` byte in the stream is followed by `00` to distinguish it from a real marker. Restart markers (`RST0`–`RST7`) appear at regular intervals to allow partial recovery from corruption. A carver must handle both correctly to measure the true extent of a JPEG.

---

## Recovery Pipeline

```
Raw byte stream (disk image, memory dump, concatenated sectors)
        |
        v
  JPEG Marker Detection
  Scan for FF D8 (SOI) candidates
        |
        v
  Pre-SOS Header Parsing
  Validate: SOI -> APP* -> DQT -> SOF -> DHT -> SOS
  Extract: dimensions, Exif, quantisation flags, Huffman flags
        |
        v
  Entropy Stream Scanning
  Walk entropy bytes respecting byte stuffing (FF 00)
  and restart markers (RST0-RST7)
  Terminate at: EOI, unexpected marker, or size bound
        |
        v
  Candidate Validation
  Apply truncation policy (allow_truncated)
  Apply EOI patching policy (append FF D9 if missing)
  Compute deterministic confidence score (0.0-1.0)
        |
        v
  Overlap Suppression
  Cluster overlapping byte ranges
  Emit the strongest candidate per cluster
  (complete > truncated > larger span > earlier start)
        |
        v
  Extraction + Report
  Write recovered JPEGs to recovered/<stem>/
  Write JSONL report with metadata per candidate
```

---

## Camera-Specific Reconstruction (Phase 2)

Generic carving preserves whatever header was found in the byte stream. For Canon IXUS 310 HS images, analysis of 19 clean reference images revealed that the following fields are **invariant across every image produced by this camera**:

- Quantisation tables (DQT) — identical 130-byte payload in all reference images
- Huffman tables (DHT) — identical 416-byte payload in all reference images
- SOF0 structure — precision=8, chroma subsampling 4:2:0 (Y: 2H×1V, Cb/Cr: 1H×1V)
- SOS scan header — 10-byte payload, always the same
- No DRI segment — this camera never emits a restart interval

Only **width and height** differ per image.

This means a recovered entropy stream can be paired with a freshly assembled camera-correct header, regardless of whether the original header survived. The result is structurally identical to what the camera would have written.

Phase 2 implements:

1. **Header builder** — assembles `SOI → DQT → SOF0 → DHT → SOS` from the camera profile with injected dimensions
2. **JPEG rebuilder** — combines a carved entropy stream with a camera-correct header and EOI
3. **Entropy offset search** — tests small byte offsets into the entropy stream to correct MCU alignment
4. **Candidate scoring** — ranks multiple reconstruction attempts automatically

---

## Architecture

```
crates/
  carve-core/          Library crate — all parsing, scanning, and recovery logic
    src/
      jpeg/
        markers.rs     JPEG marker constants and helpers
        parse.rs       Pre-SOS header parser (parse_until_sos)
        entropy.rs     Entropy stream scanner (scan_entropy_stream)
        validate.rs    Candidate validation and confidence scoring
        meta.rs        SOF metadata extraction
        marker_dump.rs Segment dump utility for camera profile analysis
        restart_scan.rs Restart marker detection and statistics
      reconstruct/
        camera_profile.rs  CameraJpegProfile — invariant camera header fields
        header_builder.rs  Build JPEG header bytes from a profile + dimensions
      scanner.rs       Top-level recovery orchestration and overlap suppression
      extract.rs       Write candidate bytes to output files
      report.rs        JSONL report serialisation
  carve/               Binary crate — CLI wrapper
    src/
      main.rs          Argument parsing, file I/O, pipeline wiring
```

**Key types:**

| Type | Description |
|------|-------------|
| `PreSosResult` | Parsed header: scan start offset, metadata flags |
| `EntropyResult` | Scanned entropy: end offset, termination reason |
| `Candidate` | Raw byte range from scanning: start, end, status |
| `ValidatedCandidate` | Enriched: confidence score, metadata flags, patch state |
| `CameraJpegProfile` | Invariant camera header fields, dimension-free |
| `JsonlRecord` | Serialisable output record |

---

## Usage

```bash
# Carve all JPEG candidates from a raw image or binary file
carve <file>

# Carve multiple files / sectors concatenated
carve sector_001.bin sector_002.bin sector_003.bin

# Glob expansion
carve "sectors/*.bin"

# Keep all overlapping candidates (skip suppression)
carve --keep-overlaps <file>

# Inspect the JPEG segment structure of a file
carve --dump <file>
carve --dump --json <file>
```

Output is written to `recovered/<input-stem>/`:

```
recovered/
  image/
    candidate_0000.jpg     Recovered JPEG (confidence: 0.95)
    candidate_0001.jpg     Recovered JPEG (confidence: 0.72, EOI patched)
    report.jsonl           Metadata for each candidate
```

Each `report.jsonl` line contains:

```json
{
  "start": 0,
  "end": 142857,
  "status": "Recovered",
  "confidence_score": 0.95,
  "missing_soi": false,
  "patched_eoi": false,
  "jpeg_meta": {
    "has_exif": true,
    "has_sof": true,
    "width": 3264,
    "height": 2448
  },
  "corruption": {
    "unexpected_marker": false,
    "truncated": false
  }
}
```

---

## Confidence Score

Each candidate receives a deterministic score from 0.0 to 1.0:

| Signal | Weight |
|--------|--------|
| SOI marker present | +0.15 |
| SOS marker present | +0.25 |
| Exif data present | +0.20 |
| SOF frame header present | +0.20 |
| EOI marker present | +0.20 |

A complete, well-formed JPEG with all five signals scores 1.0. Truncated candidates with EOI patched score lower.

---

## Current Limitations

- **Camera profile:** Canon IXUS 310 HS only (Phase 2). Other cameras use Phase 1 raw carving.
- **Fragmented images:** sectors are concatenated as input; true fragment reassembly is not yet implemented.
- **Unknown dimensions:** if SOF is missing and the image cannot be decoded, dimensions default to 0×0.
- **Extreme entropy corruption:** overwritten or physically damaged sectors cannot be recovered.
- **Progressive JPEGs:** detected and reported but not reconstructed by Phase 2.

---

## Future Work

- Restart-marker resynchronisation for mid-stream corruption recovery
- Multi-camera profile support
- Entropy-based MCU alignment scoring
- Fragment reassembly across non-contiguous sectors
- AI-based perceptual restoration for irrecoverable regions
- Progressive JPEG reconstruction

---

## Building

```bash
cargo build --release
cargo test
cargo clippy
```

Requires Rust stable (tested on 1.x).
