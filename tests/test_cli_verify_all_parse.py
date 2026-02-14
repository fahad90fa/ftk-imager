from forensic_imager.cli import build_parser


def test_verify_all_command_present() -> None:
    p = build_parser()
    a = p.parse_args(["verify-all", "--case-dir", "case"])
    assert a.cmd == "verify-all"
