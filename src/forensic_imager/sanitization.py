from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def _require(binary: str) -> None:
    if shutil.which(binary) is None:
        raise RuntimeError(f"required binary not found: {binary}")


def wipe_device_nist(device: str, passes: int = 1, verify: bool = True) -> None:
    _require("shred")
    cmd = ["shred", "-v", "-n", str(passes), "-z", device]
    subprocess.run(cmd, check=True)
    if verify:
        _require("hexdump")
        subprocess.run(["bash", "-lc", f"hexdump -n 4096 -C {device} | head -n 8"], check=True)


def wipe_device_blkdiscard(device: str) -> None:
    _require("blkdiscard")
    subprocess.run(["blkdiscard", "-f", device], check=True)


def generate_sanitization_certificate(path: Path, device: str, method: str, operator: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "Sanitization Certificate",
                "=======================",
                f"Device: {device}",
                f"Method: {method}",
                f"Operator: {operator}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
