from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path


def is_block_device(path: str) -> bool:
    st = os.stat(path)
    return stat.S_ISBLK(st.st_mode)


def _run_json(cmd: list[str]) -> dict:
    cp = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(cp.stdout)


def source_is_system_disk(device: str) -> bool:
    if not is_block_device(device):
        return False
    data = _run_json(["lsblk", "-J", "-o", "PATH,MOUNTPOINTS", device])
    stack = list(data.get("blockdevices", []) or [])
    while stack:
        d = stack.pop()
        mps = d.get("mountpoints") or []
        if any(mp == "/" for mp in mps if mp):
            return True
        stack.extend(d.get("children") or [])
    return False


def _base_disk_for_device(device: str) -> str:
    # Returns /dev/<disk> for partitions; returns itself for whole disks.
    cp = subprocess.run(["lsblk", "-no", "TYPE,PKNAME", device], check=True, capture_output=True, text=True)
    parts = cp.stdout.strip().split()
    if len(parts) >= 2:
        typ, pk = parts[0], parts[1]
        if typ == "part" and pk:
            return f"/dev/{pk}"
    return device


def _base_disk_for_path(path: Path) -> str | None:
    # Identify backing block device for a filesystem path.
    try:
        cp = subprocess.run(["findmnt", "-no", "SOURCE", "-T", str(path)], check=True, capture_output=True, text=True)
        src = cp.stdout.strip()
        if not src.startswith("/dev/"):
            return None
        # src could be /dev/nvme0n1p2; normalize to base disk
        return _base_disk_for_device(src)
    except Exception:
        return None


def ensure_destination_safe(
    *,
    source: str,
    output_path: Path,
    estimated_bytes: int,
    allow_dest_on_source: bool,
) -> None:
    if not is_block_device(source):
        return

    src_disk = _base_disk_for_device(source)
    dest_disk = _base_disk_for_path(output_path)

    if dest_disk and src_disk == dest_disk and not allow_dest_on_source:
        raise RuntimeError(f"destination is on the same base disk as source ({src_disk}); choose a different drive")

    du = shutil.disk_usage(output_path)
    # 5% headroom for filesystem overhead / metadata.
    needed = int(estimated_bytes * 1.05)
    if du.free < needed:
        raise RuntimeError(f"insufficient free space: need ~{needed} bytes, have {du.free} bytes")

    # FAT32 4GiB limit (common for removable media).
    try:
        cp = subprocess.run(["findmnt", "-no", "FSTYPE", "-T", str(output_path)], check=True, capture_output=True, text=True)
        fstype = cp.stdout.strip().lower()
        if fstype in {"vfat", "fat", "msdos"} and estimated_bytes > (4 * 1024 * 1024 * 1024 - 1):
            raise RuntimeError("destination filesystem appears to be FAT32/vfat; file size >4GiB will fail")
    except subprocess.CalledProcessError:
        pass


def estimate_source_bytes(source: str, max_bytes: int = 0) -> int:
    if max_bytes > 0:
        return int(max_bytes)

    if is_block_device(source):
        cp = subprocess.run(["lsblk", "-b", "-no", "SIZE", source], check=True, capture_output=True, text=True)
        return int(cp.stdout.strip() or "0")

    return Path(source).stat().st_size
