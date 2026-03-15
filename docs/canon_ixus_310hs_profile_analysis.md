# Canon IXUS 310 HS — JPEG Header Consistency Analysis

**Ticket:** 2.2
**Date:** 2026-03-15
**Fixtures analysed:** 19 clean reference images (from 26 fixture files; 7 could not be parsed because no recoverable JPEG was found at expected offsets)

## Method

Each fixture file is a raw disk image dump. The main JPEG in each file was located using `recover_candidates` (selecting the candidate with the largest pixel area), then `dump_jpeg_segments` was run at that offset to extract the full segment list from SOI through SOS.

All 19 successfully parsed images were compared field-by-field.

---

## Findings

### Marker ordering

**Result: 100% invariant across all 19 images.**

```
SOI → APP1 → DQT → SOF0 → DHT → SOS
```

The camera firmware always emits segments in this exact order. No APP0 (JFIF), no DRI, no COM.

---

### DQT — Quantisation tables

**Result: 100% invariant. Safe to hardcode in camera profile.**

- Count: **1 segment** per image
- Payload length: **130 bytes** (2-byte header + 128-byte table body for two packed 64-value tables)

Full DQT payload (hex):
```
00 01 01 01 02 01 01 02 02 02 02 03 02 02 03 03
06 04 03 03 03 03 07 05 08 04 06 08 08 0A 09 08
07 0B 08 0A 0E 0D 0B 0A 0A 0C 0A 08 08 0B 10 0C
0C 0D 0F 0F 0F 0F 09 0B 10 11 0F 0E 11 0D 0E 0E
0E 01 04 04 04 05 04 05 09 05 05 09 0F 0A 08 0A
0F 1A 13 09 09 13 1A 1A 1A 1A 1A 0D 1A 1A 1A 1A
1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A
1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A 1A
```

The first 65 bytes encode quantisation table 0 (luma); the next 65 bytes encode table 1 (chroma). These are Canon's fixed quality tables for this firmware version.

---

### DHT — Huffman tables

**Result: 100% invariant. Safe to hardcode in camera profile.**

- Count: **1 segment** per image
- Payload length: **416 bytes**

The single DHT segment contains all four Huffman tables packed together (DC luma, DC chroma, AC luma, AC chroma — standard JPEG baseline layout). Because the payload is identical across every image it is firmware-determined, not image-determined.

---

### SOF0 — Frame header

**Result: All non-dimensional fields 100% invariant.**

| Field | Value |
|-------|-------|
| Precision | 8-bit |
| Component count | 3 (YCbCr) |
| Y  (id=1) sampling | 0x21 → 2H × 1V (4:2:0 horizontal) |
| Cb (id=2) sampling | 0x11 → 1H × 1V |
| Cr (id=3) sampling | 0x11 → 1H × 1V |
| Y qt selector | 0 |
| Cb qt selector | 1 |
| Cr qt selector | 1 |

The chroma subsampling is **4:2:0** (Y sampled at 2× horizontal relative to Cb/Cr).

**Dimensions** (bytes 1–4 of the SOF0 payload): All 19 analysed images are **2992 × 2992** pixels. Dimensions must be treated as resolution-dependent even though this dataset happens to be uniform — they must be injected at rebuild time, not hardcoded.

---

### DRI — Restart interval

**Result: NOT PRESENT in any of the 19 images.**

The Canon IXUS 310 HS does **not** use restart markers. This means:

- No DRI segment belongs in the camera profile.
- RST0–RST7 markers will not appear in Canon IXUS 310 HS entropy streams.
- Restart-aware repair (ticket 2.8 follow-on) is not required for this camera.

---

### SOS — Start of scan

**Result: 100% invariant.**

- Payload (hex): `03 01 00 02 11 03 11 00 3F 00`

Decoded:
- 3 components in scan
- Y  (id=1): DC table 0, AC table 0
- Cb (id=2): DC table 1, AC table 1
- Cr (id=3): DC table 1, AC table 1
- Spectral selection: 0–63 (full baseline scan)

---

### APP1 — Exif

Present in all 19 images. Contains per-image metadata (timestamp, GPS, thumbnail). **Not needed for JPEG decoding** — will not be included in the reconstructed header. Omitting it produces a fully decodeable image.

---

## Decision: One reusable header template is sufficient

All firmware-determined fields are identical across every image tested. A single `CameraJpegProfile` for the Canon IXUS 310 HS can safely hardcode:

- The DQT payload (130 bytes)
- The DHT payload (416 bytes)
- SOF0 precision, component count, sampling factors, qt selectors
- SOS component mapping
- Marker order: `SOI → DQT → SOF0 → DHT → SOS`

Width and height are injected at rebuild time (from the carved candidate's `width` / `height` fields, or from a known reference if those are unavailable).

---

## Camera Profile Specification

```rust
// Marker order
SOI                              // FF D8
DQT (130-byte payload, above)    // FF DB ...
SOF0 (inject width/height)       // FF C0 ...
DHT (416-byte payload, above)    // FF C4 ...
SOS (10-byte payload, above)     // FF DA ...
// [entropy data follows]
// [EOI: FF D9]
```

No APP0, no APP1, no DRI. This is the minimal valid header for Canon IXUS 310 HS baseline JPEGs.

---

## Implication for Ticket 2.8

Since DRI is absent from all test images, **RST markers are not expected in Canon IXUS 310 HS entropy streams**. The restart marker scanner (ticket 2.8) is still useful for confirming this on carved (potentially corrupt) streams, but the Canon IXUS 310 HS profile should **not** include a DRI segment.
