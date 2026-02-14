from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .audit import write_audit_event
from .hashing import hash_file


def capture_memory_lime(lime_module: Path, output_path: Path, fmt: str = "lime", audit_log: Path | None = None) -> dict[str, str]:
    if fmt not in {"lime", "padded", "raw"}:
        raise ValueError("fmt must be one of: lime, padded, raw")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if audit_log is not None:
        write_audit_event(audit_log, "memory.capture.start", lime_module=str(lime_module), output=str(output_path), fmt=fmt)

    insmod_arg = f"path={output_path} format={fmt}"
    subprocess.run(["insmod", str(lime_module), insmod_arg], check=True)

    # LiME module name isn't guaranteed to match filename stem; best-effort removal.
    try:
        subprocess.run(["rmmod", lime_module.stem], check=True)
    except subprocess.CalledProcessError:
        # Fall back: rmmod lime if common name.
        subprocess.run(["rmmod", "lime"], check=False)

    if not output_path.exists():
        raise RuntimeError("memory output file was not created")

    hashes = hash_file(output_path, algorithms=("md5", "sha1", "sha256"))
    hashes["bytes"] = str(output_path.stat().st_size)
    hashes["path"] = str(output_path)

    if audit_log is not None:
        write_audit_event(audit_log, "memory.capture.complete", **hashes)

    return hashes
