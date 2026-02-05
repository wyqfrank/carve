# Carve

> A two-stage digital camera photo recovery system that combines deterministic binary-level file carving with AI-based perceptual restoration.

---

## Overview

Carve explicitly separates **provable data recovery** from **plausible reconstruction**, ensuring transparency about what is truly recovered versus what is intelligently restored.

## Target Recovery Scenarios

Carve addresses real-world camera failure modes:

- **Interrupted writes** — incomplete file saves due to power loss or card removal
- **Corrupted file allocation tables** — damaged filesystem metadata
- **Partially overwritten sectors** — storage reused before full erasure
- **Truncated image files** — incomplete data due to storage limits or errors

## Philosophy

The system does not claim to recover original ground-truth data when it no longer exists.

Instead, Carve:

1. **Deterministically extracts** all recoverable image data at the binary level
2. **Optionally applies AI-based restoration** to improve visual quality where corruption is irrecoverable

---

## License

See [LICENSE](LICENSE) for details.
