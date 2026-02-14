from pathlib import Path

from forensic_imager.acquire import parse_hash_file


def test_parse_hash_file(tmp_path: Path) -> None:
    p = tmp_path / "image.hashes"
    p.write_text("md5=aaa\nsha1=bbb\nbytes=123\n", encoding="utf-8")
    out = parse_hash_file(p)
    assert out["md5"] == "aaa"
    assert out["sha1"] == "bbb"
    assert out["bytes"] == "123"
