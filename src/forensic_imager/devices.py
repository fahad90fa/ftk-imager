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


def _run_text(cmd: list[str]) -> str:
    cp = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if cp.returncode != 0:
        err = (cp.stderr or "").strip()
        return f"(failed: {err})\n"
    return cp.stdout


def _tool_exists(name: str) -> bool:
    cp = subprocess.run(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"], check=False)
    return cp.returncode == 0


def list_block_devices() -> list[dict[str, Any]]:
    data = _run_json(["lsblk", "-J", "-o", "NAME,KNAME,PATH,SIZE,TYPE,MODEL,SERIAL,VENDOR,RM,RO,MOUNTPOINTS,FSTYPE"])
    return data.get("blockdevices", [])


def get_device_info(device: str) -> dict[str, Any]:
    dev_path = Path(device)
    if not dev_path.exists():
        raise FileNotFoundError(device)
    mode = os.stat(dev_path).st_mode
    if not stat.S_ISBLK(mode):
        return {
            "type": "regular_file",
            "path": str(dev_path),
            "size": dev_path.stat().st_size,
        }

    lsblk = _run_json(
        ["lsblk", "-J", "-o", "NAME,KNAME,PATH,SIZE,TYPE,MODEL,SERIAL,VENDOR,RM,RO,MOUNTPOINTS,FSTYPE,UUID,PARTUUID,PTTYPE,PTUUID", str(dev_path)]
    )
    result: dict[str, Any] = {"lsblk": lsblk}

    try:
        cp = subprocess.run(["udevadm", "info", "--query=property", "--name", str(dev_path)], check=True, capture_output=True, text=True)
        props = {}
        for line in cp.stdout.splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            props[k] = v
        result["udev"] = props
    except (subprocess.CalledProcessError, FileNotFoundError):
        result["udev"] = {}

    # Partition table / filesystem metadata helpers (best-effort).
    if _tool_exists("blkid"):
        result["blkid"] = _run_text(["blkid", "-p", str(dev_path)])
    else:
        result["blkid"] = "(missing blkid)\n"

    if _tool_exists("sfdisk"):
        result["partition_table_sfdisk"] = _run_text(["sfdisk", "-d", str(dev_path)])
    else:
        result["partition_table_sfdisk"] = "(missing sfdisk)\n"

    if _tool_exists("smartctl"):
        # smartctl usually wants the whole disk, but allow it to try anyway.
        result["smartctl"] = _run_text(["smartctl", "-a", str(dev_path)])
    else:
        result["smartctl"] = "(missing smartctl)\n"

    if _tool_exists("hdparm"):
        result["hdparm_identify"] = _run_text(["hdparm", "-I", str(dev_path)])
    else:
        result["hdparm_identify"] = "(missing hdparm)\n"

    return result


def ensure_not_rw_mounted(device: str) -> None:
    mode = os.stat(device).st_mode
    if not stat.S_ISBLK(mode):
        return
    data = _run_json(["lsblk", "-J", "-o", "PATH,MOUNTPOINTS,RO", device])
    for dev in data.get("blockdevices", []):
        ro = str(dev.get("ro", "1"))
        mounts = dev.get("mountpoints") or []
        mounts = [m for m in mounts if m]
        if mounts and ro == "0":
            raise RuntimeError(f"Device appears mounted read-write: {device} -> {mounts}")
