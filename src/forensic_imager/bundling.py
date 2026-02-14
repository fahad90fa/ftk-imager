from __future__ import annotations

import tarfile
from pathlib import Path


def create_case_bundle(case_dir: Path, output_path: Path) -> Path:
    case_dir = case_dir.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tarfile.open(output_path, "w:gz") as tf:
        for p in sorted(case_dir.rglob("*")):
            if not p.is_file():
                continue
            arcname = str(p.relative_to(case_dir))
            tf.add(p, arcname=arcname, recursive=False)

    return output_path
