# Epic 2.11 — Decode-Aware JPEG Validation & Scoring

## Goal

Replace entropy-only scoring with decode-aware image evaluation, enabling the system to select the visually correct reconstruction, not just statistically plausible byte streams.

## Tickets

- Ticket 2.11.1 — Integrate JPEG Decoder
- Ticket 2.11.2 — Implement Decode-Based Image Metrics
- Ticket 2.11.3 — Combine Decode-Based Scoring Function
- Ticket 2.11.4 — Integrate Decode Scoring into Reconstruction Pipeline
- Ticket 2.11.5 — Update Output & Reporting
- Ticket 2.11.6 — Benchmark Decode-Based Scoring

## Summary — What you should do right now

Start with:

👉 2.11.1 → 2.11.2 → 2.11.3

That gets you:
- decoding
- metrics
- scoring

Then:

👉 2.11.4 integration

Everything else is polish.
