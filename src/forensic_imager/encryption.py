from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

from .audit import utc_now


def _require(binary: str) -> None:
    if shutil.which(binary) is None:
        raise RuntimeError(f"required binary not found: {binary}")


def validate_password_strength(password: str, min_len: int = 12) -> tuple[bool, str]:
    if len(password) < min_len:
        return False, f"password too short (minimum {min_len} characters)"

    classes = 0
    classes += 1 if re.search(r"[a-z]", password) else 0
    classes += 1 if re.search(r"[A-Z]", password) else 0
    classes += 1 if re.search(r"[0-9]", password) else 0
    classes += 1 if re.search(r"[^A-Za-z0-9]", password) else 0

    if classes < 3:
        return False, "password must include at least 3 character classes (lower/upper/digit/symbol)"
    return True, "ok"


def generate_keyfile(path: Path, bytes_len: int = 48) -> Path:
    if bytes_len < 32:
        raise ValueError("bytes_len must be at least 32")

    path.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(bytes_len)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(secret + "\n", encoding="utf-8")
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp, path)
    return path


def _sha256_file(path: Path, chunk_size: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def write_encryption_metadata(
    metadata_path: Path,
    *,
    input_path: Path,
    output_path: Path,
    password_source: str,
    iter_count: int,
) -> Path:
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "created_at": utc_now(),
        "algorithm": "aes-256-cbc",
        "kdf": "pbkdf2",
        "kdf_iterations": iter_count,
        "input_path": str(input_path),
        "output_path": str(output_path),
        "input_size": input_path.stat().st_size,
        "output_size": output_path.stat().st_size,
        "input_sha256": _sha256_file(input_path),
        "output_sha256": _sha256_file(output_path),
        "password_source": password_source,
    }
    metadata_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return metadata_path


def encrypt_file_aes256(
    input_path: Path,
    output_path: Path,
    password: str,
    *,
    iter_count: int = 200000,
    metadata_out: Path | None = None,
    password_source: str = "prompt",
    allow_weak_password: bool = False,
) -> None:
    _require("openssl")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    ok, reason = validate_password_strength(password)
    if not ok and not allow_weak_password:
        raise RuntimeError(f"weak password rejected: {reason}")

    cmd = [
        "openssl",
        "enc",
        "-aes-256-cbc",
        "-pbkdf2",
        "-iter",
        str(iter_count),
        "-salt",
        "-in",
        str(input_path),
        "-out",
        str(output_path),
        "-pass",
        "stdin",
    ]
    subprocess.run(cmd, check=True, input=password + "\n", text=True)

    if metadata_out is not None:
        write_encryption_metadata(
            metadata_out,
            input_path=input_path,
            output_path=output_path,
            password_source=password_source,
            iter_count=iter_count,
        )


def decrypt_file_aes256(input_path: Path, output_path: Path, password: str, *, iter_count: int = 200000) -> None:
    _require("openssl")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "openssl",
        "enc",
        "-d",
        "-aes-256-cbc",
        "-pbkdf2",
        "-iter",
        str(iter_count),
        "-in",
        str(input_path),
        "-out",
        str(output_path),
        "-pass",
        "stdin",
    ]
    subprocess.run(cmd, check=True, input=password + "\n", text=True)
