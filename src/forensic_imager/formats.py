from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def _require(binary: str) -> None:
    if shutil.which(binary) is None:
        raise RuntimeError(f"required binary not found: {binary}")


def acquire_e01(
    source: str,
    output_prefix: Path,
    case_number: str,
    evidence_number: str,
    examiner: str,
    description: str,
    notes: str,
    compression_level: int = 6,
    segment_size_mb: int = 2048,
) -> None:
    _require("ewfacquire")
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "ewfacquire",
        "-u",  # unattended
        "-f",
        "encase6",
        "-c",
        str(compression_level),
        "-S",
        str(segment_size_mb),
        "-C",
        case_number,
        "-E",
        examiner,
        "-e",
        evidence_number,
        "-D",
        description,
        "-N",
        notes,
        "-t",
        str(output_prefix),
        source,
    ]
    subprocess.run(cmd, check=True)


def verify_e01(image_path: Path) -> str:
    _require("ewfverify")
    cp = subprocess.run(["ewfverify", str(image_path)], check=True, capture_output=True, text=True)
    return cp.stdout


def convert_image(input_path: Path, output_path: Path, to_format: str) -> None:
    if to_format == "raw":
        _require("ewfexport")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["ewfexport", "-u", "-t", str(output_path.with_suffix("")), "-f", "raw", str(input_path)]
        subprocess.run(cmd, check=True)
        return

    if to_format == "e01":
        # Convert raw to E01 using ewfacquirestream if available.
        _require("ewfacquirestream")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with input_path.open("rb") as fin:
            subprocess.run(
                ["ewfacquirestream", "-u", "-f", "encase6", "-t", str(output_path.with_suffix(""))],
                stdin=fin,
                check=True,
            )
        return

    if to_format == "aff":
        _require("afconvert")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["afconvert", str(input_path), str(output_path)], check=True)
        return

    raise ValueError("to_format must be one of: raw, e01, aff")


def inspect_aff(path: Path) -> dict[str, str]:
    _require("afinfo")
    cp = subprocess.run(["afinfo", str(path)], check=True, capture_output=True, text=True)
    return {"path": str(path), "info": cp.stdout}


def export_format_metadata(output_path: Path, data: dict[str, str]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
