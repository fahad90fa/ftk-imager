from forensic_imager.cli import build_parser


def test_case_command_present() -> None:
    parser = build_parser()
    args = parser.parse_args([
        "case",
        "init",
        "--case-dir",
        "caseA",
        "--case-number",
        "C1",
        "--examiner",
        "examiner",
    ])
    assert args.cmd == "case"
    assert args.case_cmd == "init"
