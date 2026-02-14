# Project Dossier: Parrot Forensic Imager

This document is the comprehensive technical and operational reference for the **Parrot Forensic Imager** project. It is intended for maintainers, reviewers, forensic practitioners, and legal/QA stakeholders who need a deep understanding of what the tool does, how it works, and how it supports forensic integrity.

## 1. Purpose and Scope

Parrot Forensic Imager is a Linux-first forensic acquisition toolkit designed for Parrot OS and Debian-based distributions. The goals are:

- Provide **bit-for-bit** evidence acquisition comparable to FTK Imager workflows.
- Preserve **forensic integrity** through read-only acquisition, multiple cryptographic hashes, and strict verification.
- Produce **court-defensible artifacts**: audit trails, system-state snapshots, manifests, and sealed case outputs.
- Offer both **CLI** (automation, scripting) and **GUI** (operator usability) workflows.

### In-scope

- Raw/DD acquisition from block devices and regular files.
- Hash computation (MD5, SHA-1, SHA-256; optional SHA-512) and verification.
- Resumable imaging and range imaging.
- Case management and chain-of-custody artifact generation.
- Tamper-evident audit logging with verification.
- Tool-backed E01 (libewf tools) and AFF (afflib tools) workflows.
- Preview and extraction using Sleuth Kit tools.
- Read-only mount helper.
- Memory acquisition wrapper around LiME.

### Out-of-scope (currently)

- Full native (in-process) EWF/AFF implementations without external tooling.
- Filesystem-aware “allocated-only” imaging with formal semantics.
- Full GUI parity with all FTK Imager features (we provide a similar layout/workflow, but not every feature).
- Signed/reproducible release pipeline (planned).

## 2. High-Level Architecture

The project is intentionally modular:

### 2.1 Core C Imaging Engine

- **File**: `src/core/imager_core.c`
- **Binary**: `build/forensic-imager-core`

Responsibilities:

- High-throughput reading from source evidence (block device or file).
- Writing to destination image file.
- One-pass hashing using OpenSSL EVP:
  - MD5, SHA-1, SHA-256; optional SHA-512
- Range imaging:
  - `start_offset`
  - `max_bytes`
- Append mode:
  - Used for resume workflows
- Progress telemetry:
  - JSON lines to stderr with `progress_bytes`, `total_bytes`, `speed_bps`
- Read error continuity behavior:
  - Logs read errors, attempts to skip, writes zero-filled 512 bytes and continues.

Design rationale:

- Keep the fastest and most sensitive acquisition logic in C.
- Keep orchestration, reporting, GUI, and integrations in Python for flexibility.

### 2.2 Python Orchestration Layer

All Python modules live under `src/forensic_imager/`.

Key modules:

- `cli.py`: CLI command surface and wiring
- `acquire.py`: case workflow orchestration (runs core, generates artifacts, verifies hashes, resume logic)
- `audit.py`: tamper-evident hash-chained audit logging and verification
- `devices.py`: block device inventory and metadata capture
- `writeblock.py`: software write-block controls using `blockdev`
- `case_mgmt.py`: case workspace init/show and case manifest
- `seal.py`: case sealing and verification (ties audit, manifest, artifacts, and image together)
- `bundling.py`: tar.gz case bundling
- `system_state.py`: workstation system-state snapshot for defensibility
- `preview.py`: preview wrappers (Sleuth Kit)
- `extract.py`: file export from images (Sleuth Kit `icat`)
- `mounting.py`: loop setup and read-only mounting helper
- `memory.py`: LiME memory capture wrapper + hashing + audit
- `formats.py`: tool-backed E01/AFF integrations
- `encryption.py`: OpenSSL AES helpers + password policy + metadata sidecar
- `doctor.py`: environment/dependency diagnostics
- `gui.py`: Qt GUI (PyQt6 if available, otherwise PyQt5) with FTK-like layout

## 3. Forensic Integrity Model

### 3.1 Evidence Read-Only Guarantee

- Acquisition uses OS-level read-only open (`O_RDONLY`).
- The tool refuses to acquire from a device that appears mounted read-write.
- Optional software write-block enforcement:
  - `--require-writeblock` fails unless `lsblk` reports RO=1
  - `--try-writeblock` attempts `blockdev --setro` (requires root)

Important note:

- Hardware write blockers remain the gold standard for defensibility. Software write-blocking reduces risk but does not replace hardware controls in high-stakes cases.

### 3.2 One-Pass Multi-Hash Strategy

During acquisition the core computes multiple hashes simultaneously to avoid repeated reads. The orchestrator also seals final image hashes for long-term verification.

### 3.3 Audit Trail and Tamper Evidence

- Operator audit events are written to `audit.jsonl`.
- Each event contains:
  - `seq`, `prev_hash`, `event_hash`
- `verify-audit` validates:
  - sequence correctness
  - hash linking
  - SHA-256 event hash correctness
- By default verification is **strict**: unsigned events are rejected.

Engine telemetry is separated:

- `core_audit.jsonl` contains engine-side events and is not part of the operator audit chain.

### 3.4 Case Sealing

`case seal` generates a case seal file (`exports/case_seal.json`) that:

- Forces a fresh manifest generation (`exports/manifest.json`)
- Verifies the audit chain
- Records SHA-256 hashes and sizes of:
  - `audit.jsonl`, `core_audit.jsonl`
  - `case.json`, `acquisition_report.txt`, `image.hashes`
  - `exports/manifest.json`
  - image file itself (when available)

`case verify` recomputes and fails on any mismatch.

## 4. Operator Workflows

### 4.1 Recommended Raw Acquisition Workflow

1. Create case workspace:
   - `case init`
2. Ensure evidence is write-blocked (hardware preferred).
3. Acquire:
   - `acquire` with case metadata
4. Verify:
   - `verify` (image vs `image.hashes`)
   - `verify-audit`
5. Seal:
   - `case seal`
6. Handoff:
   - `case verify`
   - `case bundle`

### 4.2 Resume Workflow

- If acquisition is interrupted, `resume` continues from the existing output size.
- `checkpoint.json` is updated during acquisition with progress and offsets.
- Resume validates checkpoint offsets against image size to prevent accidental corruption.

### 4.3 E01 Workflow (Tool-Backed)

E01 acquisition uses `ewfacquire` and supports segmentation/compression metadata via that toolchain. Verification uses `ewfverify`.

### 4.4 Preview and Export

Preview and export are implemented using Sleuth Kit tools:

- `mmls` to find partitions
- `fls` to list entries
- `icat` to export and preview file content

This avoids mounting and reduces evidence modification risks.

### 4.5 Read-Only Mount Helper

`mount-ro` sets up a read-only loop device and mounts with conservative options:

- Always: `ro,nosuid,nodev,noexec`
- Adds `noload` only for ext2/3/4

### 4.6 Memory Capture

`memory-capture` wraps LiME:

- Runs `insmod` with `path=... format=...`
- Attempts `rmmod`
- Hashes the resulting dump and optionally writes audit events.

## 5. Produced Artifacts

Typical case directory artifacts include:

- `images/*.dd` (raw) or `*.E01` (tool-backed)
- `image.hashes` (final raw-image hashes)
- `audit.jsonl` + `audit.jsonl.chain`
- `core_audit.jsonl`
- `checkpoint.json`
- `device_metadata.json` (lsblk + udev + best-effort: blkid/sfdisk/smartctl/hdparm)
- `system_state.txt` (workstation snapshot)
- `case.json` (structured case metadata + tool fingerprints)
- `acquisition_report.txt` (human readable)
- `exports/manifest.json` (hashed file listing)
- `exports/case_seal.json` (seal)
- `exports/*.tgz` (bundle output, if created)

## 6. Dependencies

The project uses a mixture of built-in tools and optional forensic toolchains.

### Required for core raw acquisition

- `gcc`, `make`
- OpenSSL dev headers (`libssl-dev`) for building the C core
- Runtime: `openssl` (for some features), `util-linux` (`lsblk`, `losetup`, `blkid`, `sfdisk`)

### Optional (feature dependent)

- GUI:
  - `python3-pyqt5` (Parrot/Debian)
- Sleuth Kit:
  - `sleuthkit` (`mmls`, `fls`, `icat`, `fsstat`)
- E01:
  - `libewf-tools` (`ewfacquire`, `ewfverify`, `ewfexport`)
- AFF:
  - `afflib-tools` (`afconvert`, `afinfo`)
- SMART/drive identify:
  - `smartmontools` (`smartctl`)
  - `hdparm`
- PDF:
  - `pandoc` or `wkhtmltopdf`

Use `doctor` to see what’s missing on a specific machine.

## 7. Security and Privilege Model

This tool tries to minimize privileged operations:

- Most operations run as unprivileged user.
- Root-required operations include:
  - setting write-block: `blockdev --setro/--setrw`
  - mounting loop devices
  - LiME memory capture
  - wiping/sanitization

Security considerations:

- Encryption avoids passing secrets on the command line; password is passed to OpenSSL via stdin.
- GUI uses env-var password injection for CLI subprocesses and clears password field after launch.
- Inputs should be treated as untrusted; more hardening and sandboxing is planned.

## 8. Testing and QA

Unit tests live in `tests/` and cover:

- hashing and hash-file parsing
- CLI surface parsing for many commands
- audit chain tamper detection
- case manifest and seal tamper detection

Limitations of test environment:

- Full device imaging, LiME capture, and mounting require privileged/system-specific environments.
- Tool-backed features depend on installed toolchains.

## 9. Known Limitations and Design Tradeoffs

- E01/AFF are integrated via standard external utilities rather than native libraries.
- “Allocated-only” imaging is not implemented because it changes the meaning of “bit-for-bit image” and requires filesystem-aware semantics and careful defensibility framing.
- Some operations require the operator to select correct partition offsets; the GUI helps via `mmls` parsing.

## 10. Roadmap

High-impact next steps:

- Replace tool-backed EWF/AFF paths with native library integrations (optional build features).
- Expand GUI workflows:
  - multi-step imaging wizard with validation and warnings
  - integrated case selection and artifact browsing
  - accessibility/i18n work
- Add reproducible builds and signed releases.
- Add better network acquisition modes with authenticated encryption and better resume semantics.
- Add stronger device safety rails:
  - explicit “system disk” lockout mode
  - destination sanity checks (prevent imaging to same disk by default)

## 11. Project Layout

- `src/core/` – C acquisition engine
- `src/forensic_imager/` – Python CLI/GUI and feature modules
- `tests/` – unit tests
- `packaging/` – Debian packaging skeleton
- `README.md` – operator-facing overview
- `CONTRIBUTING.md` – contribution guidelines
- `LICENSE` – Apache-2.0

