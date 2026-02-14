# Architecture

## Core

- `src/core/imager_core.c`
  - Read-only source acquisition
  - Simultaneous hash calculation (MD5/SHA1/SHA256/SHA512)
  - Range imaging, append/resume mode, progress telemetry
  - Bad-read continuity behavior

## Python Orchestration

- `acquire.py`: raw acquisition workflow + case artifacts
- `acquire.py`: raw acquisition workflow + checkpoint persistence + case artifacts
- `case_mgmt.py`: case workspace init/show and hashed manifest export
- `audit.py`: tamper-evident hash-chained audit log + strict verification policy
- `gui.py`: PyQt6 operator GUI for device inventory and acquisition/resume orchestration
- `gui.py`: PyQt6 operator GUI including Security workflows (keygen/encrypt/decrypt/audit verify)
- `encryption.py`: AES encryption/decryption, strong-password policy, keyfile generation, metadata sidecar
- `cli.py`: all operator commands
- `devices.py`: lsblk/udev metadata and safety checks
- `preview.py`: read-only preview wrappers
- `mounting.py`: read-only loop mount helpers
- `memory.py`: LiME integration wrapper
- `formats.py`: E01/AFF tooling wrappers and conversion
- `network.py`: SSH-based remote imaging stream acquisition
- `encryption.py`: OpenSSL AES wrappers
- `sanitization.py`: wipe/sanitization actions and certificates
- `reporting.py`: text and PDF report generation wrappers

## Integrity Model

- Source opened with `O_RDONLY`
- RW-mounted source devices rejected
- Audit artifacts persisted in case folder
- `checkpoint.json` persisted during acquisition for resume visibility/state
- `audit.jsonl` is hash-chained; `verify-audit` validates sequence and link integrity
- Full-image hash sealing after acquisition for legal verification

## Operational Notes

Several advanced features call external forensic tools rather than native embedded libraries.
This keeps the codebase modular while preserving interoperability with standard Linux forensic stacks.
