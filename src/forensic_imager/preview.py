from __future__ import annotations

import subprocess
from pathlib import Path


def _run_if_available(binary: str, args: list[str]) -> str:
    cp = subprocess.run(["bash", "-lc", f"command -v {binary} >/dev/null 2>&1"], check=False)
    if cp.returncode != 0:
        return f"[{binary}] not installed\n"
    run = subprocess.run([binary, *args], check=False, capture_output=True, text=True)
    if run.returncode != 0:
        return f"[{binary}] failed: {run.stderr.strip()}\n"
    return run.stdout


def preview_evidence(path: Path, limit_entries: int = 128) -> str:
    out = []
    out.append("== Partition Layout (mmls) ==\n")
    out.append(_run_if_available("mmls", [str(path)]))

    out.append("\n== Filesystem Stats (fsstat) ==\n")
    out.append(_run_if_available("fsstat", [str(path)]))

    out.append("\n== Recursive Listing (fls) ==\n")
    out.append(_run_if_available("fls", ["-r", "-m", "/", str(path)]))

    text = "".join(out)
    lines = text.splitlines()
    if len(lines) > limit_entries:
        lines = lines[:limit_entries] + ["... output truncated ..."]
    return "\n".join(lines) + "\n"
