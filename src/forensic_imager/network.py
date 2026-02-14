from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path


def acquire_over_ssh(
    host: str,
    source_path: str,
    output_image: Path,
    hash_path: Path,
    use_sudo: bool = True,
    buffer_size: int = 4 * 1024 * 1024,
) -> dict[str, str]:
    output_image.parent.mkdir(parents=True, exist_ok=True)
    hash_path.parent.mkdir(parents=True, exist_ok=True)

    remote_cmd = f"dd if={source_path} bs={buffer_size} iflag=fullblock status=none"
    if use_sudo:
        remote_cmd = f"sudo {remote_cmd}"

    proc = subprocess.Popen(
        ["ssh", host, remote_cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if proc.stdout is None:
        raise RuntimeError("failed to open ssh stdout")

    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    copied = 0
    started = time.time()

    with output_image.open("wb") as out:
        while True:
            chunk = proc.stdout.read(buffer_size)
            if not chunk:
                break
            out.write(chunk)
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
            copied += len(chunk)
            elapsed = max(time.time() - started, 1e-6)
            speed = copied / elapsed
            print(json.dumps({"progress_bytes": copied, "speed_bps": speed}))

    rc = proc.wait()
    stderr_text = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
    if rc != 0:
        raise RuntimeError(f"ssh acquisition failed ({rc}): {stderr_text.strip()}")

    hashes = {
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest(),
        "copied_bytes": str(copied),
    }
    with hash_path.open("w", encoding="utf-8") as f:
        for k, v in hashes.items():
            f.write(f"{k}={v}\n")

    return hashes
