from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .audit import utc_now


def init_case_workspace(case_dir: Path, case_number: str, examiner: str, description: str, notes: str) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("images", "reports", "logs", "memory", "exports"):
        (case_dir / sub).mkdir(exist_ok=True)

    workspace = {
        "case_number": case_number,
        "examiner": examiner,
        "description": description,
        "notes": notes,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "acquisitions": [],
    }
    path = case_dir / "case_workspace.json"
    path.write_text(json.dumps(workspace, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_case_workspace(case_dir: Path) -> dict[str, Any]:
    path = case_dir / "case_workspace.json"
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def show_case(case_dir: Path) -> dict[str, Any]:
    workspace = load_case_workspace(case_dir)
    artifacts = {
        "images": sorted(str(p.relative_to(case_dir)) for p in (case_dir / "images").glob("**/*") if p.is_file()),
        "reports": sorted(str(p.relative_to(case_dir)) for p in (case_dir / "reports").glob("**/*") if p.is_file()),
        "logs": sorted(str(p.relative_to(case_dir)) for p in (case_dir / "logs").glob("**/*") if p.is_file()),
    }
    return {"workspace": workspace, "artifacts": artifacts}


def _sha256_file(path: Path, chunk_size: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def export_case_manifest(case_dir: Path, output_path: Path) -> Path:
    case_dir = case_dir.resolve()
    output_path = output_path.resolve()

    entries: list[dict[str, Any]] = []
    for p in sorted(case_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.resolve() == output_path:
            continue
        entries.append(
            {
                "path": str(p.relative_to(case_dir)),
                "size": p.stat().st_size,
                "sha256": _sha256_file(p),
            }
        )

    payload = {
        "generated_at": utc_now(),
        "case_dir": str(case_dir),
        "file_count": len(entries),
        "entries": entries,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path
