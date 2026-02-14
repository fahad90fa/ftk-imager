from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any


def _run_json(cmd: list[str]) -> dict[str, Any]:
    cp = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(cp.stdout)


def is_block_device(path: str) -> bool:
    st = os.stat(path)
    return stat.S_ISBLK(st.st_mode)


def get_ro_status(device: str) -> bool:
    if not is_block_device(device):
        raise RuntimeError(f"not a block device: {device}")
    data = _run_json(["lsblk", "-J", "-o", "PATH,RO", device])
    devs = data.get("blockdevices", [])
    if not devs:
        raise RuntimeError(f"device not found in lsblk: {device}")
    ro = str(devs[0].get("ro", "0"))
    return ro == "1"


def set_readonly(device: str) -> None:
    if not is_block_device(device):
        raise RuntimeError(f"not a block device: {device}")
    # Requires root.
    subprocess.run(["blockdev", "--setro", device], check=True)


def set_readwrite(device: str) -> None:
    if not is_block_device(device):
        raise RuntimeError(f"not a block device: {device}")
    # Requires root.
    subprocess.run(["blockdev", "--setrw", device], check=True)


def require_readonly(device: str) -> None:
    if not is_block_device(device):
        return
    if not get_ro_status(device):
        raise RuntimeError(f"device is not read-only (RO=0): {device}")
