from __future__ import annotations

import importlib.util
import os
import platform
import shutil
from dataclasses import dataclass


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""


def _bin(name: str, fix: str = "") -> Check:
    path = shutil.which(name)
    return Check(
        name=f"bin:{name}",
        ok=path is not None,
        detail=path or "missing",
        fix=fix,
    )


def _py_module(name: str, fix: str = "") -> Check:
    spec = importlib.util.find_spec(name)
    return Check(
        name=f"py:{name}",
        ok=spec is not None,
        detail=str(spec.origin) if spec and spec.origin else ("found" if spec else "missing"),
        fix=fix,
    )


def run_doctor() -> list[Check]:
    checks: list[Check] = []

    checks.append(Check("platform", True, f"{platform.system()} {platform.release()} ({platform.machine()})"))
    checks.append(Check("session", True, os.environ.get("XDG_SESSION_TYPE", "unknown")))
    checks.append(Check("display", True, os.environ.get("DISPLAY", "")))

    # GUI stack
    checks.append(_py_module("PyQt5", "sudo apt install -y python3-pyqt5 python3-pyqt5.sip"))
    checks.append(_py_module("PyQt6", "(optional) install PyQt6 if available in your repos"))

    # Core imaging dependencies
    checks.append(_bin("lsblk", "sudo apt install -y util-linux"))
    checks.append(_bin("udevadm", "sudo apt install -y udev"))
    checks.append(_bin("openssl", "sudo apt install -y openssl"))
    checks.append(_bin("blkid", "sudo apt install -y util-linux"))
    checks.append(_bin("sfdisk", "sudo apt install -y util-linux"))
    checks.append(_bin("smartctl", "sudo apt install -y smartmontools"))
    checks.append(_bin("hdparm", "sudo apt install -y hdparm"))

    # Sleuth Kit (preview/export)
    checks.append(_bin("mmls", "sudo apt install -y sleuthkit"))
    checks.append(_bin("fls", "sudo apt install -y sleuthkit"))
    checks.append(_bin("icat", "sudo apt install -y sleuthkit"))

    # Mounting helpers
    checks.append(_bin("losetup", "sudo apt install -y util-linux"))
    checks.append(_bin("mount", "sudo apt install -y mount"))

    # E01/AFF toolchains
    checks.append(_bin("ewfacquire", "sudo apt install -y libewf-tools"))
    checks.append(_bin("ewfverify", "sudo apt install -y libewf-tools"))
    checks.append(_bin("ewfexport", "sudo apt install -y libewf-tools"))
    checks.append(_bin("afconvert", "sudo apt install -y afflib-tools"))
    checks.append(_bin("afinfo", "sudo apt install -y afflib-tools"))

    # Network imaging
    checks.append(_bin("ssh", "sudo apt install -y openssh-client"))

    # Reporting
    checks.append(_bin("pandoc", "sudo apt install -y pandoc"))
    checks.append(_bin("wkhtmltopdf", "sudo apt install -y wkhtmltopdf"))

    # Sanitization
    checks.append(_bin("shred", "sudo apt install -y coreutils"))
    checks.append(_bin("blkdiscard", "sudo apt install -y util-linux"))

    return checks
