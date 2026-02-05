# carve
Carve is a two-stage digital camera photo recovery system that combines deterministic binary-level file carving with AI-based perceptual restoration, explicitly separating provable data recovery from plausible reconstruction.

Carve targets real-world camera failure modes such as:

interrupted writes

corrupted file allocation tables

partially overwritten sectors

truncated image files

The system does not claim to recover original ground-truth data when it no longer exists. Instead, it:

deterministically extracts all recoverable image data at the binary level

optionally applies AI-based restoration to improve visual quality where corruption is irrecoverable
