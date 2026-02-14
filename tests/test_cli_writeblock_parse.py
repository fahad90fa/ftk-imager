from forensic_imager.cli import build_parser


def test_writeblock_commands_present() -> None:
    p = build_parser()
    a = p.parse_args(["writeblock", "status", "--device", "/dev/sda"])
    assert a.cmd == "writeblock"
    assert a.writeblock_cmd == "status"


def test_acquire_writeblock_flags_present() -> None:
    p = build_parser()
    a = p.parse_args([
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
        "--require-writeblock",
    ])
    assert a.require_writeblock is True
