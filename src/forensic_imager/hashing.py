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
