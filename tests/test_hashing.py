from pathlib import Path

from forensic_imager.acquire import verify_image
from forensic_imager.hashing import hash_file, hash_segmented_prefix


def test_hash_file(tmp_path: Path) -> None:
    p = tmp_path / "sample.bin"
    p.write_bytes(b"abc")

    hashes = hash_file(p, algorithms=("md5", "sha1", "sha256"))

    assert hashes["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert hashes["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_segmented_prefix_and_verify(tmp_path: Path) -> None:
    prefix = tmp_path / "evidence.dd"
    (tmp_path / "evidence.dd.001").write_bytes(b"ab")
    (tmp_path / "evidence.dd.002").write_bytes(b"c")

    seg = hash_segmented_prefix(prefix, algorithms=("md5", "sha1", "sha256"))
    assert seg["segments"] == "2"
    assert seg["bytes"] == "3"
    assert seg["md5"] == "900150983cd24fb0d6963f7d28e17f72"

    # verify_image should auto-detect prefix segments if prefix file doesn't exist.
    hf = tmp_path / "image.hashes"
    hf.write_text(
        "md5=900150983cd24fb0d6963f7d28e17f72\n"
        "sha1=a9993e364706816aba3e25717850c26c9cd0d89d\n"
        "sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
        encoding="utf-8",
    )
    got = verify_image(prefix, hf)
    assert got["md5"] == "900150983cd24fb0d6963f7d28e17f72"
