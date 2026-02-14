from pathlib import Path

from forensic_imager.hashing import hash_file


def test_hash_file(tmp_path: Path) -> None:
    p = tmp_path / "sample.bin"
    p.write_bytes(b"abc")

    hashes = hash_file(p, algorithms=("md5", "sha1", "sha256"))

    assert hashes["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert hashes["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
