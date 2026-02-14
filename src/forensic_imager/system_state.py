from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

from .audit import utc_now


def _run(cmd: list[str]) -> str:
    cp = subprocess.run(cmd, check=False, capture_output=True, text=True)
    out = (cp.stdout or "").strip()
    err = (cp.stderr or "").strip()
    if cp.returncode != 0:
        return f"$ {' '.join(cmd)}\n(exit={cp.returncode})\n{out}\n{err}\n\n"
    return f"$ {' '.join(cmd)}\n{out}\n\n"


def capture_system_state(output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    chunks: list[str] = []
    chunks.append("Forensic System State Snapshot\n")
    chunks.append("==============================\n\n")
    chunks.append(f"captured_at_utc: {utc_now()}\n")
    chunks.append(f"hostname: {platform.node()}\n")
    chunks.append(f"platform: {platform.platform()}\n")
    chunks.append(f"pid: {os.getpid()}\n\n")

    chunks.append(_run(["id"]))
    chunks.append(_run(["uname", "-a"]))
    chunks.append(_run(["lsb_release", "-a"]))
    chunks.append(_run(["mount"]))
    chunks.append(_run(["df", "-h"]))
    chunks.append(_run(["lsblk", "-o", "NAME,PATH,SIZE,TYPE,MODEL,SERIAL,RM,RO,MOUNTPOINTS,FSTYPE"]))
    chunks.append(_run(["ip", "addr"]))
    chunks.append(_run(["ip", "route"]))
    chunks.append(_run(["ps", "aux", "--sort=-%mem"]))
    chunks.append(_run(["lsmod"]))

    # Avoid huge output by tailing dmesg.
    chunks.append(_run(["bash", "-lc", "dmesg | tail -n 200"]))

    output_path.write_text("".join(chunks), encoding="utf-8")
    return output_path
