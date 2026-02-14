from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .audit import write_audit_event


def export_file_from_image(
    *,
    image_path: Path,
    start_sector: int,
    inode: str,
    output_path: Path,
    audit_log: Path | None = None,
) -> None:
    if shutil.which("icat") is None:
        raise RuntimeError("required binary not found: icat (install sleuthkit)")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["icat", "-o", str(start_sector), str(image_path), str(inode)]
    with output_path.open("wb") as out:
        cp = subprocess.run(cmd, check=False, stdout=out, stderr=subprocess.PIPE)

    if cp.returncode != 0:
        err = (cp.stderr or b"").decode("utf-8", errors="replace").strip()
        raise RuntimeError(err or "icat failed")

    if audit_log is not None:
        write_audit_event(
            audit_log,
            "export.file",
            image_path=str(image_path),
            start_sector=int(start_sector),
            inode=str(inode),
            output_path=str(output_path),
        )
