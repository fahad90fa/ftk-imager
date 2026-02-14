from forensic_imager.cli import build_parser


def test_doctor_command_present() -> None:
    parser = build_parser()
    args = parser.parse_args(["doctor"])
    assert args.cmd == "doctor"
