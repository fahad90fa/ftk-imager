from pathlib import Path

from forensic_imager.encryption import generate_keyfile, validate_password_strength


def test_password_strength_policy() -> None:
    ok, _ = validate_password_strength("StrongPass#2026")
    assert ok is True

    weak, reason = validate_password_strength("short")
    assert weak is False
    assert "short" in reason


def test_generate_keyfile(tmp_path: Path) -> None:
    path = tmp_path / "key.txt"
    generate_keyfile(path, bytes_len=32)
    data = path.read_text(encoding="utf-8").strip()
    assert len(data) >= 32
