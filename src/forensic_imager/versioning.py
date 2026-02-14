from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from . import __version__


def _sha256_file(path: Path, chunk_size: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def get_version_info(core_binary: Path | None = None) -> dict[str, str]:
    info = {
        "package_version": __version__,
    }

    if core_binary and core_binary.exists():
        info["core_binary"] = str(core_binary)
        info["core_sha256"] = _sha256_file(core_binary)

    try:
        cp = subprocess.run(["openssl", "version"], check=False, capture_output=True, text=True)
        info["openssl"] = (cp.stdout or "").strip() or "unknown"
    except Exception:
        info["openssl"] = "unknown"

    return info
