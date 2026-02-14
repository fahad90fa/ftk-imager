from forensic_imager.cli import build_parser


def test_version_command_present() -> None:
    p = build_parser()
    a = p.parse_args(["version"])
    assert a.cmd == "version"
