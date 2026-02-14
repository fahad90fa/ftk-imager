# Parrot Forensic Imager

Professional-grade forensic acquisition toolkit for Debian/Parrot OS with a hardened C imaging core and an FTK-Imager-like GUI. Designed for **bit-for-bit** imaging workflows with **auditability**, **verification**, and **court-defensible artifacts**.

This project aims to provide an FTK Imager class experience on Linux: imaging + verification + preview + export + case management.

## Key Capabilities

- **Bitstream imaging (Raw/DD)** from files or block devices (`/dev/*`)
  - One-pass hashing during acquisition: **MD5 + SHA-1 + SHA-256** (optional SHA-512)
  - **Resume** interrupted acquisitions
  - **Range imaging** via start offset + max bytes
- **E01 support (tool-backed)** via `libewf` utilities (`ewfacquire`, `ewfverify`, `ewfexport`)
- **AFF support (tool-backed)** via `afflib` utilities (`afconvert`, `afinfo`)
- **Tamper-evident audit log**
  - Hash-chained `audit.jsonl` with a strict verifier (`verify-audit`)
  - Separate `core_audit.jsonl` for engine telemetry
- **Case workspace + chain-of-custody artifacts**
  - `case init/show/manifest`
  - `case seal/verify` to seal key artifacts and detect any later modification
  - `case bundle` to export a `tar.gz` case bundle
- **Read-only preview + file export (Sleuth Kit)**
  - Partition listing: `mmls`
  - Listing: `fls`
  - Export: `icat` (`export-file`)
- **Read-only mounting helper** (`mount-ro` / `unmount-ro`)
- **Software write-block controls** (`writeblock status/set/clear`) and acquisition enforcement
- **Memory acquisition (LiME wrapper)** with hashing + optional audit logging (`memory-capture`)
- **Security utilities**
  - AES-256-CBC encryption/decryption wrappers using OpenSSL
  - Password policy + keyfile generator (`keygen`)
  - Optional encryption metadata sidecar
- **GUI**
  - Evidence Tree (evidence → partitions)
  - File list
  - Tabs: Properties / Hex / Text / Log
  - Imaging wizard + E01 option
  - Export selected file
  - Mount selected partition (RO)
  - Diagnostics (`doctor`)

## Forensic Safety / Legal Notes

- The imaging core opens the source **read-only** at the OS layer (`O_RDONLY`).
- The tool will block imaging if the source appears **mounted read-write**.
- For maximum defensibility, use **hardware write blockers** when available.
- If you image your **system disk**, do not store the destination image on the same disk (risk: filling disk and destabilizing the system).
- Operations like `writeblock set`, `mount-ro`, and memory capture require **root**.

This tool is intended to support best practices; your lab SOPs, jurisdiction, and evidence handling rules still apply.

## Quick Start

### 1) Build the C core

```bash
make clean
make core
```

### 2) Run tests

```bash
PYTHONPATH=src python3 -m pytest -q
```

### 3) Run diagnostics (recommended)

```bash
PYTHONPATH=src python3 -m forensic_imager.cli doctor
```

### 4) Run the GUI (Parrot/Debian)

```bash
sudo apt update
sudo apt install -y python3-pyqt5 python3-pyqt5.sip

# Optional (preview/export/browsing):
sudo apt install -y sleuthkit

PYTHONPATH=src python3 -m forensic_imager.gui
```

## CLI Usage

All CLI commands can be run without installing the package system-wide:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli --help
```

### Case Workflow (Recommended)

Initialize a case workspace:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli case init \
  --case-dir /evidence/CASE-001 \
  --case-number CASE-001 \
  --examiner "Analyst"
```

Acquire a Raw/DD image:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli acquire \
  --source /dev/sdb \
  --output-image /evidence/CASE-001/images/disk.dd \
  --output-dir /evidence/CASE-001 \
  --case-number CASE-001 \
  --evidence-number EVD-001 \
  --examiner "Analyst" \
  --description "Laptop seizure" \
  --notes "Acquired in lab" \
  --core-binary build/forensic-imager-core
```

Resume an interrupted acquisition:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli resume \
  --source /dev/sdb \
  --output-image /evidence/CASE-001/images/disk.dd \
  --output-dir /evidence/CASE-001 \
  --case-number CASE-001 \
  --evidence-number EVD-001 \
  --examiner "Analyst" \
  --core-binary build/forensic-imager-core
```

Verify hashes:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli verify \
  --image /evidence/CASE-001/images/disk.dd \
  --hash-file /evidence/CASE-001/image.hashes
```

Verify the tamper-evident audit chain:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli verify-audit --log /evidence/CASE-001/audit.jsonl
```

Seal the case (recommended before handoff):

```bash
PYTHONPATH=src python3 -m forensic_imager.cli case seal --case-dir /evidence/CASE-001
PYTHONPATH=src python3 -m forensic_imager.cli case verify --case-dir /evidence/CASE-001
```

Bundle the case directory:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli case bundle \
  --case-dir /evidence/CASE-001 \
  --output /evidence/CASE-001.tgz
```

### Write Blocking (Software)

Check RO status:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli writeblock status --device /dev/sdb
```

Set RO (root required):

```bash
sudo PYTHONPATH=src python3 -m forensic_imager.cli writeblock set --device /dev/sdb
```

Enforce write-block during imaging:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli acquire ... --require-writeblock

# or (root) set + enforce:
sudo PYTHONPATH=src python3 -m forensic_imager.cli acquire ... --try-writeblock --require-writeblock
```

### E01 Acquisition (libewf tools)

```bash
sudo apt install -y libewf-tools

PYTHONPATH=src python3 -m forensic_imager.cli acquire-e01 \
  --source /dev/sdb \
  --output-prefix /evidence/CASE-001/images/disk \
  --case-number CASE-001 \
  --evidence-number EVD-001 \
  --examiner "Analyst" \
  --description "Laptop seizure" \
  --notes "Acquired in lab"
```

Verify E01:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli verify-e01 --image /evidence/CASE-001/images/disk.E01
```

### Preview / Export (Sleuth Kit)

Install:

```bash
sudo apt install -y sleuthkit
```

Preview:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli preview --path /evidence/CASE-001/images/disk.dd
```

Export a file:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli export-file \
  --image /evidence/CASE-001/images/disk.dd \
  --start-sector 2048 \
  --inode 5-128-1 \
  --output /evidence/CASE-001/exports/some_file.bin \
  --audit-log /evidence/CASE-001/audit.jsonl
```

### Read-Only Mount Helper

```bash
sudo PYTHONPATH=src python3 -m forensic_imager.cli mount-ro \
  --image /evidence/CASE-001/images/disk.dd \
  --mount-point /mnt/evidence \
  --offset 1048576

sudo PYTHONPATH=src python3 -m forensic_imager.cli unmount-ro \
  --mount-point /mnt/evidence \
  --loop-device /dev/loopX
```

### Memory Capture (LiME)

```bash
sudo PYTHONPATH=src python3 -m forensic_imager.cli memory-capture \
  --lime-module /path/to/lime.ko \
  --output /evidence/CASE-001/memory/memory.lime \
  --format lime \
  --audit-log /evidence/CASE-001/audit.jsonl
```

## Acquisition Artifacts (Raw Workflow)

When you run `acquire`, the case folder typically contains:

- `images/<name>.dd` – raw image output
- `image.hashes` – MD5/SHA1/SHA256 (and optional SHA512) of the final image
- `audit.jsonl` + `audit.jsonl.chain` – tamper-evident operator audit chain
- `core_audit.jsonl` – C-core telemetry log
- `checkpoint.json` – progress/resume state
- `device_metadata.json` – `lsblk`, `udev`, plus best-effort `smartctl/hdparm/blkid/sfdisk`
- `system_state.txt` – workstation snapshot at acquisition start
- `case.json` – structured case metadata
- `acquisition_report.txt` – human-readable report
- `exports/manifest.json` – case file manifest (if generated)
- `exports/case_seal.json` – case seal (if generated)

## Troubleshooting

- GUI says PyQt missing:
  - Install `python3-pyqt5 python3-pyqt5.sip`
- Preview/export fails:
  - Install `sleuthkit` (`mmls`, `fls`, `icat`)
- E01 fails:
  - Install `libewf-tools`
  - Ensure your source device exists (`list-devices`)
- Run `doctor` to see missing dependencies:
  - `PYTHONPATH=src python3 -m forensic_imager.cli doctor`

## Development

- C core: `src/core/imager_core.c` (OpenSSL EVP hashing, range imaging, resume append mode)
- Python orchestration: `src/forensic_imager/*`
- Tests: `tests/`

## Packaging

Debian packaging skeleton lives in `packaging/debian/`.

## Roadmap (Not Yet Fully Native)

- Native in-process EWF/AFF libraries (current implementation wraps standard toolchains)
- Full “allocated-only” imaging semantics (filesystem-aware logical acquisition)
- Expanded GUI wizards (multi-step workflows, accessibility/i18n polish)
- Signed release artifacts and reproducible build pipeline

## License

Apache-2.0. See `LICENSE`.

## Contributing

See `CONTRIBUTING.md`.
