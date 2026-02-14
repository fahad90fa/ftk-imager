from forensic_imager.cli import build_parser


def test_case_bundle_command_present() -> None:
    p = build_parser()
    a = p.parse_args(["case", "bundle", "--case-dir", "c", "--output", "o.tgz"])
    assert a.cmd == "case"
    assert a.case_cmd == "bundle"
