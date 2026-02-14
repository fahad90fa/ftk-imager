from __future__ import annotations

from pathlib import Path

from .acquire import verify_image
from .audit import verify_audit_chain
from .seal import verify_case_seal


def verify_case_all(case_dir: Path) -> dict[str, object]:
    case_dir = case_dir.resolve()

    results: dict[str, object] = {"case_dir": str(case_dir)}

    audit_log = case_dir / "audit.jsonl"
    results["audit"] = verify_audit_chain(audit_log, require_all_signed=True)

    # Image verification (raw workflow)
    case_json = case_dir / "case.json"
    if case_json.exists():
        import json

        data = json.loads(case_json.read_text(encoding="utf-8"))
        image_path = Path(str(data.get("image_path") or ""))
        hash_path = case_dir / "image.hashes"
        if image_path.exists() and hash_path.exists():
            results["image_hashes"] = verify_image(image_path, hash_path)

    # Case seal verification (if present)
    seal_path = case_dir / "exports" / "case_seal.json"
    if seal_path.exists():
        results["seal"] = verify_case_seal(case_dir, seal_path)

    return results
