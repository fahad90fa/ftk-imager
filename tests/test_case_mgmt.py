from pathlib import Path

from forensic_imager.case_mgmt import export_case_manifest, init_case_workspace, load_case_workspace


def test_case_init_and_manifest(tmp_path: Path) -> None:
    case_dir = tmp_path / "CASE-1"
    ws = init_case_workspace(case_dir, case_number="CASE-1", examiner="alice", description="d", notes="n")
    assert ws.exists()

    workspace = load_case_workspace(case_dir)
    assert workspace["case_number"] == "CASE-1"

    sample = case_dir / "images" / "disk.dd"
    sample.write_bytes(b"abc")

    manifest = case_dir / "exports" / "manifest.json"
    export_case_manifest(case_dir, manifest)
    assert manifest.exists()
    text = manifest.read_text(encoding="utf-8")
    assert "disk.dd" in text
