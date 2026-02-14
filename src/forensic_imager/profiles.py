from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_PROFILE_DIR = Path.home() / ".config" / "forensic-imager" / "profiles"


def save_profile(name: str, data: dict[str, Any], profile_dir: Path = DEFAULT_PROFILE_DIR) -> Path:
    profile_dir.mkdir(parents=True, exist_ok=True)
    path = profile_dir / f"{name}.json"
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_profile(name: str, profile_dir: Path = DEFAULT_PROFILE_DIR) -> dict[str, Any]:
    path = profile_dir / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def list_profiles(profile_dir: Path = DEFAULT_PROFILE_DIR) -> list[str]:
    if not profile_dir.exists():
        return []
    return sorted(p.stem for p in profile_dir.glob("*.json"))
