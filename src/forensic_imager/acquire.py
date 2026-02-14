from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import utc_now, write_audit_event
from .devices import ensure_not_rw_mounted, get_device_info
from .hashing import hash_file
from .hashing import hash_segmented_prefix
from .badsectors import write_bad_sector_maps
from .safety import ensure_destination_safe, estimate_source_bytes, source_is_system_disk
from .reporting import generate_text_report
from .system_state import capture_system_state
from .versioning import get_version_info


@dataclass
class AcquireOptions:
    source: str
    output_image: Path
    output_dir: Path
    case_number: str
    evidence_number: str
    examiner: str
    description: str
    notes: str
    buffer_size: int = 4 * 1024 * 1024
    sha512: bool = False
    core_binary: Path = Path("build/forensic-imager-core")
    start_offset: int = 0
    max_bytes: int = 0
    append_mode: bool = False
    progress_interval: int = 1
    require_writeblock: bool = False
    try_writeblock: bool = False
    auto_seal: bool = False
    allow_system_disk: bool = False
    allow_dest_on_source: bool = False
    split_bytes: int = 0
    read_error_mode: int = 0
    read_retries: int = 3


def parse_hash_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _is_block_device(path: str) -> bool:
    st = os.stat(path)
    return stat.S_ISBLK(st.st_mode)


def _write_checkpoint(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def load_checkpoint(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_core(opts: AcquireOptions, hash_path: Path, audit_log: Path, checkpoint_path: Path) -> None:
    cmd = [
        str(opts.core_binary),
        opts.source,
        str(opts.output_image),
        str(hash_path),
        str(audit_log),
        str(opts.buffer_size),
        "1" if opts.sha512 else "0",
        str(opts.start_offset),
        str(opts.max_bytes),
        "1" if opts.append_mode else "0",
        str(opts.progress_interval),
        str(opts.split_bytes),
        str(opts.read_error_mode),
        str(opts.read_retries),
    ]
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
    if proc.stderr is not None:
        for line in proc.stderr:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "progress_bytes" in evt:
                progress_bytes = int(evt.get("progress_bytes", 0))
                total_bytes = int(evt.get("total_bytes", 0))
                speed_bps = float(evt.get("speed_bps", 0.0))
                absolute_offset = opts.start_offset + progress_bytes
                _write_checkpoint(
                    checkpoint_path,
                    {
                        "state": "running",
                        "source": opts.source,
                        "output_image": str(opts.output_image),
                        "output_dir": str(opts.output_dir),
                        "start_offset": opts.start_offset,
                        "progress_bytes": progress_bytes,
                        "absolute_offset": absolute_offset,
                        "total_bytes": total_bytes,
                        "speed_bps": speed_bps,
                        "updated_at": utc_now(),
                    },
                )
                print(
                    json.dumps(
                        {
                            "progress_bytes": progress_bytes,
                            "total_bytes": total_bytes,
                            "absolute_offset": absolute_offset,
                            "speed_bps": speed_bps,
                        }
                    )
                )

    rc = proc.wait()
    if rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)


def _compute_image_hashes(image_path: Path, include_sha512: bool) -> dict[str, str]:
    algorithms = ("md5", "sha1", "sha256", "sha512") if include_sha512 else ("md5", "sha1", "sha256")
    if image_path.exists():
        return hash_file(image_path, algorithms=algorithms)
    # Support segmented raw output: <prefix>.001, <prefix>.002...
    seg1 = Path(f"{image_path}.001")
    if seg1.exists():
        return hash_segmented_prefix(image_path, algorithms=algorithms)
    raise FileNotFoundError(image_path)


def run_acquisition(opts: AcquireOptions) -> dict[str, str]:
    opts.output_dir.mkdir(parents=True, exist_ok=True)

    audit_log = opts.output_dir / "audit.jsonl"
    core_audit_log = opts.output_dir / "core_audit.jsonl"
    metadata_path = opts.output_dir / "device_metadata.json"
    hash_path = opts.output_dir / "image.hashes"
    report_path = opts.output_dir / "acquisition_report.txt"
    case_path = opts.output_dir / "case.json"
    checkpoint_path = opts.output_dir / "checkpoint.json"
    system_state_path = opts.output_dir / "system_state.txt"

    # Capture system state snapshot early for legal defensibility.
    capture_system_state(system_state_path)
    tool_info = get_version_info(opts.core_binary)

    write_audit_event(
        audit_log,
        "acquire.start",
        source=opts.source,
        output_image=str(opts.output_image),
        case_number=opts.case_number,
        evidence_number=opts.evidence_number,
        examiner=opts.examiner,
        start_offset=opts.start_offset,
        max_bytes=opts.max_bytes,
        append_mode=opts.append_mode,
        require_writeblock=opts.require_writeblock,
        try_writeblock=opts.try_writeblock,
        system_state_path=str(system_state_path),
        tool_info=tool_info,
    )

    ensure_not_rw_mounted(opts.source)
    if source_is_system_disk(opts.source) and not opts.allow_system_disk:
        raise RuntimeError("source appears to be the system disk (contains mountpoint '/'); use --allow-system-disk to override")

    # Preflight destination validation to prevent catastrophic operator mistakes.
    total_estimated = estimate_source_bytes(opts.source, max_bytes=opts.max_bytes)
    # If we're starting at an offset (resume or partial acquisition), only the remaining
    # bytes must fit on the destination filesystem.
    if opts.max_bytes > 0:
        estimated = int(opts.max_bytes)
    else:
        estimated = max(int(total_estimated) - int(opts.start_offset), 0)
    ensure_destination_safe(
        source=opts.source,
        output_path=opts.output_image.parent,
        estimated_bytes=estimated,
        allow_dest_on_source=opts.allow_dest_on_source,
    )
    if opts.require_writeblock or opts.try_writeblock:
        # Best-effort software write blocking. Requires root if try_writeblock=True.
        from .writeblock import require_readonly, set_readonly  # local import to avoid hard dep in non-root tests

        if opts.try_writeblock:
            try:
                set_readonly(opts.source)
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(f"failed to set software write-block: {exc}") from exc
        require_readonly(opts.source)
    metadata = get_device_info(opts.source)
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")

    started_at = utc_now()
    _run_core(opts, hash_path=hash_path, audit_log=core_audit_log, checkpoint_path=checkpoint_path)
    segment_hashes = parse_hash_file(hash_path)

    # Extract a formal bad-sector map for reporting/defensibility.
    badmap = write_bad_sector_maps(opts.output_dir, core_audit_log)

    # Full-image hashes are legal/reporting-grade values used for long-term verification.
    full_hashes = _compute_image_hashes(opts.output_image, include_sha512=opts.sha512)

    completed_at = utc_now()
    case_data = {
        "case_number": opts.case_number,
        "evidence_number": opts.evidence_number,
        "examiner": opts.examiner,
        "description": opts.description,
        "notes": opts.notes,
        "source": opts.source,
        "source_is_block_device": _is_block_device(opts.source),
        "image_path": str(opts.output_image),
        "metadata_path": str(metadata_path),
        "system_state_path": str(system_state_path),
        "tool_info": tool_info,
        "bad_sectors": badmap,
        "audit_log": str(audit_log),
        "core_audit_log": str(core_audit_log),
        "hashes": full_hashes,
        "segment_hashes": {k: v for k, v in segment_hashes.items() if k in {"md5", "sha1", "sha256", "sha512"}},
        "read_errors": int(segment_hashes.get("read_errors", "0")),
        "copied_bytes": int(segment_hashes.get("copied_bytes", "0")),
        "start_offset": int(segment_hashes.get("start_offset", "0")),
        "absolute_end_offset": int(segment_hashes.get("absolute_end_offset", "0")),
        "started_at": started_at,
        "completed_at": completed_at,
        "tool_version": "0.18.0",
        "hostname": os.uname().nodename,
    }
    case_path.write_text(json.dumps(case_data, indent=2, sort_keys=True), encoding="utf-8")
    _write_checkpoint(
        checkpoint_path,
        {
            "state": "complete",
            "source": opts.source,
            "output_image": str(opts.output_image),
            "output_dir": str(opts.output_dir),
            "absolute_offset": case_data["absolute_end_offset"],
            "copied_bytes": case_data["copied_bytes"],
            "read_errors": case_data["read_errors"],
            "completed_at": completed_at,
        },
    )

    workspace_path = opts.output_dir / "case_workspace.json"
    if workspace_path.exists():
        workspace = json.loads(workspace_path.read_text(encoding="utf-8"))
        acquisitions = workspace.get("acquisitions", [])
        acquisitions.append(
            {
                "started_at": started_at,
                "completed_at": completed_at,
                "source": opts.source,
                "image_path": str(opts.output_image),
                "hash_path": str(hash_path),
                "case_path": str(case_path),
                "report_path": str(report_path),
            }
        )
        workspace["acquisitions"] = acquisitions
        workspace["updated_at"] = completed_at
        workspace_path.write_text(json.dumps(workspace, indent=2, sort_keys=True), encoding="utf-8")

    with hash_path.open("w", encoding="utf-8") as f:
        f.write(f"md5={full_hashes['md5']}\n")
        f.write(f"sha1={full_hashes['sha1']}\n")
        f.write(f"sha256={full_hashes['sha256']}\n")
        if opts.sha512:
            f.write(f"sha512={full_hashes['sha512']}\n")
        f.write(f"read_errors={case_data['read_errors']}\n")
        f.write(f"copied_bytes={case_data['copied_bytes']}\n")

    generate_text_report(report_path, case_data)

    if opts.auto_seal:
        try:
            from .seal import create_case_seal

            create_case_seal(opts.output_dir)
        except Exception as exc:  # noqa: BLE001
            # Sealing is best-effort; acquisition is already complete.
            write_audit_event(audit_log, "case.seal.failed", error=str(exc))

    write_audit_event(
        audit_log,
        "acquire.complete",
        source=opts.source,
        output_image=str(opts.output_image),
        copied_bytes=case_data["copied_bytes"],
        read_errors=case_data["read_errors"],
    )

    return {
        "audit_log": str(audit_log),
        "core_audit_log": str(core_audit_log),
        "hash_path": str(hash_path),
        "metadata_path": str(metadata_path),
        "report_path": str(report_path),
        "case_path": str(case_path),
    }


def run_resume(
    source: str,
    output_image: Path,
    output_dir: Path,
    case_number: str,
    evidence_number: str,
    examiner: str,
    description: str,
    notes: str,
    buffer_size: int,
    sha512: bool,
    core_binary: Path,
    progress_interval: int,
    require_writeblock: bool = False,
    try_writeblock: bool = False,
    auto_seal: bool = False,
    allow_system_disk: bool = False,
    allow_dest_on_source: bool = False,
    read_error_mode: int = 0,
    read_retries: int = 3,
) -> dict[str, str]:
    # Resume is only supported for a single raw output file (no segmentation).
    if not output_image.exists():
        # If a segmented acquisition exists, make the failure mode explicit.
        if Path(f"{output_image}.001").exists():
            raise RuntimeError("resume is not supported for segmented outputs; re-run acquisition without --split-bytes")
        start_offset = 0
    else:
        start_offset = output_image.stat().st_size
    checkpoint_path = output_dir / "checkpoint.json"
    if checkpoint_path.exists():
        checkpoint = load_checkpoint(checkpoint_path)
        cp_offset = int(checkpoint.get("absolute_offset", start_offset))
        if cp_offset != start_offset:
            raise RuntimeError(
                f"resume mismatch: output image size={start_offset} but checkpoint absolute_offset={cp_offset}"
            )
    opts = AcquireOptions(
        source=source,
        output_image=output_image,
        output_dir=output_dir,
        case_number=case_number,
        evidence_number=evidence_number,
        examiner=examiner,
        description=description,
        notes=notes,
        buffer_size=buffer_size,
        sha512=sha512,
        core_binary=core_binary,
        start_offset=start_offset,
        max_bytes=0,
        append_mode=start_offset > 0,
        progress_interval=progress_interval,
        require_writeblock=require_writeblock,
        try_writeblock=try_writeblock,
        auto_seal=auto_seal,
        allow_system_disk=allow_system_disk,
        allow_dest_on_source=allow_dest_on_source,
        split_bytes=0,
        read_error_mode=read_error_mode,
        read_retries=read_retries,
    )
    return run_acquisition(opts)


def verify_image(image_path: Path, hash_path: Path) -> dict[str, str]:
    expected = parse_hash_file(hash_path)
    wanted = tuple(a for a in ("md5", "sha1", "sha256", "sha512") if a in expected)
    if image_path.exists():
        current = hash_file(image_path, algorithms=wanted)
    elif Path(f"{image_path}.001").exists():
        current = hash_segmented_prefix(image_path, algorithms=wanted)
    else:
        raise FileNotFoundError(image_path)
    mismatch = {k: (expected.get(k), current.get(k)) for k in wanted if expected.get(k) != current.get(k)}
    if mismatch:
        raise RuntimeError(f"hash mismatch: {mismatch}")
    # Preserve only hash fields for compatibility with existing callers.
    return {k: current[k] for k in wanted}
