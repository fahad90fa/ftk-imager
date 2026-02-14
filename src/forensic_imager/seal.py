from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .audit import utc_now, verify_audit_chain
from .case_mgmt import export_case_manifest
from .hashing import hash_file


def _sha256_file(path: Path, chunk_size: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_hash_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _verify_image_hashes(image_path: Path, hash_path: Path) -> dict[str, str]:
    expected = _parse_hash_file(hash_path)
    wanted = tuple(a for a in ("md5", "sha1", "sha256", "sha512") if a in expected)
    current = hash_file(image_path, algorithms=wanted)
    mismatch = {k: (expected.get(k), current.get(k)) for k in wanted if expected.get(k) != current.get(k)}
    if mismatch:
        raise RuntimeError(f"hash mismatch: {mismatch}")
    return current


def create_case_seal(case_dir: Path, seal_path: Path | None = None, manifest_path: Path | None = None) -> Path:
    case_dir = case_dir.resolve()
    if seal_path is None:
        seal_path = case_dir / "exports" / "case_seal.json"
    if manifest_path is None:
        manifest_path = case_dir / "exports" / "manifest.json"

    # Ensure a fresh manifest exists.
    export_case_manifest(case_dir, manifest_path)

    audit_log = case_dir / "audit.jsonl"
    image_hashes = case_dir / "image.hashes"
    case_json = case_dir / "case.json"
    report = case_dir / "acquisition_report.txt"
    core_audit = case_dir / "core_audit.jsonl"

    audit_status = verify_audit_chain(audit_log, require_all_signed=True)

    files: list[dict[str, Any]] = []
    for p in [audit_log, core_audit, case_json, report, image_hashes, manifest_path]:
        if not p.exists():
            continue
        files.append({"path": str(p.relative_to(case_dir)), "sha256": _sha256_file(p), "size": p.stat().st_size})

    # Verify image hash if we have the typical raw workflow artifacts.
    image_path: Path | None = None
    if case_json.exists():
        try:
            data = json.loads(case_json.read_text(encoding="utf-8"))
            if data.get("image_path"):
                image_path = Path(str(data["image_path"]))
        except Exception:
            image_path = None

    image_verified = False
    if image_path is not None and image_path.exists() and image_hashes.exists():
        _verify_image_hashes(image_path, image_hashes)
        files.append({"path": str(image_path), "sha256": _sha256_file(image_path), "size": image_path.stat().st_size})
        image_verified = True

    payload = {
        "created_at": utc_now(),
        "case_dir": str(case_dir),
        "audit_last_hash": audit_status["last_hash"],
        "audit_chained_events": audit_status["chained_events"],
        "image_verified": image_verified,
        "files": sorted(files, key=lambda x: x["path"]),
    }

    seal_path.parent.mkdir(parents=True, exist_ok=True)
    seal_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return seal_path


def verify_case_seal(case_dir: Path, seal_path: Path | None = None) -> dict[str, Any]:
    case_dir = case_dir.resolve()
    if seal_path is None:
        seal_path = case_dir / "exports" / "case_seal.json"

    if not seal_path.exists():
        raise FileNotFoundError(seal_path)

    seal = json.loads(seal_path.read_text(encoding="utf-8"))

    audit_log = case_dir / "audit.jsonl"
    audit_status = verify_audit_chain(audit_log, require_all_signed=True)
    if seal.get("audit_last_hash") != audit_status.get("last_hash"):
        raise RuntimeError("audit last_hash mismatch (audit log changed)")

    mismatches: list[dict[str, Any]] = []
    for entry in seal.get("files", []):
        p = Path(str(entry["path"]))
        full = p if p.is_absolute() else (case_dir / p)
        if not full.exists():
            mismatches.append({"path": str(entry["path"]), "error": "missing"})
            continue
        sha = _sha256_file(full)
        if sha != entry.get("sha256"):
            mismatches.append({"path": str(entry["path"]), "expected": entry.get("sha256"), "actual": sha})

    if mismatches:
        raise RuntimeError(f"case seal verification failed: {mismatches}")

    return {"valid": True, "seal": str(seal_path), "checked_files": len(seal.get("files", []))}
