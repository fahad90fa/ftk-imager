from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def extract_bad_sectors(core_audit_log: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not core_audit_log.exists():
        return out

    for line in core_audit_log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if evt.get("message") != "read_error":
            continue
        offset = int(evt.get("offset", 0))
        errno_str = str(evt.get("errno", ""))
        ts = str(evt.get("ts", ""))
        out.append(
            {
                "ts": ts,
                "offset": offset,
                "sector": offset // 512,
                "errno": errno_str,
            }
        )

    return out


def write_bad_sector_maps(case_dir: Path, core_audit_log: Path) -> dict[str, str]:
    case_dir.mkdir(parents=True, exist_ok=True)
    bad = extract_bad_sectors(core_audit_log)

    json_path = case_dir / "bad_sectors.json"
    txt_path = case_dir / "bad_sectors.txt"

    json_path.write_text(json.dumps({"count": len(bad), "entries": bad}, indent=2, sort_keys=True), encoding="utf-8")

    lines = [f"Bad Sector Map (count={len(bad)})", ""]
    for e in bad:
        lines.append(f"ts={e.get('ts')} sector={e.get('sector')} offset={e.get('offset')} errno={e.get('errno')}")
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {"bad_sectors_json": str(json_path), "bad_sectors_txt": str(txt_path), "bad_sectors_count": str(len(bad))}
