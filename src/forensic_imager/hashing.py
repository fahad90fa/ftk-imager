from __future__ import annotations

import hashlib
from pathlib import Path


SUPPORTED = ("md5", "sha1", "sha256", "sha512")


def hash_file(path: Path, algorithms: tuple[str, ...] = ("md5", "sha1", "sha256"), chunk_size: int = 4 * 1024 * 1024) -> dict[str, str]:
    hs = {name: hashlib.new(name) for name in algorithms}
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            for h in hs.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hs.items()}


def hash_segmented_prefix(prefix_path: Path, algorithms: tuple[str, ...] = ("md5", "sha1", "sha256"), chunk_size: int = 4 * 1024 * 1024) -> dict[str, str]:
    """
    Hashes a segmented raw image created as:
      <prefix>.001, <prefix>.002, ... until the first missing segment.
    """
    hs = {name: hashlib.new(name) for name in algorithms}
    idx = 1
    total = 0
    while True:
        seg = Path(f"{prefix_path}.{idx:03d}")
        if not seg.exists():
            break
        with seg.open("rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                for h in hs.values():
                    h.update(chunk)
                total += len(chunk)
        idx += 1

    if idx == 1:
        raise FileNotFoundError(f"no segments found for prefix: {prefix_path}")

    out = {name: h.hexdigest() for name, h in hs.items()}
    out["bytes"] = str(total)
    out["segments"] = str(idx - 1)
    return out
