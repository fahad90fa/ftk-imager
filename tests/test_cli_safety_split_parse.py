from forensic_imager.cli import build_parser


def test_acquire_safety_and_split_flags_present() -> None:
    p = build_parser()
    a = p.parse_args(
        [
            "acquire",
            "--source",
            "/dev/sda",
            "--output-image",
            "out.dd",
            "--output-dir",
            "case",
            "--case-number",
            "C",
            "--evidence-number",
            "E",
            "--examiner",
            "X",
            "--allow-system-disk",
            "--allow-dest-on-source",
            "--split-bytes",
            "1048576",
            "--fail-fast-bad-sectors",
            "--read-retries",
            "5",
        ]
    )
    assert a.allow_system_disk is True
    assert a.allow_dest_on_source is True
    assert a.split_bytes == 1048576
    assert a.fail_fast_bad_sectors is True
    assert a.read_retries == 5
