from forensic_imager.cli import build_parser


def test_verify_audit_command_present() -> None:
    parser = build_parser()
    args = parser.parse_args(["verify-audit", "--log", "case/audit.jsonl"])
    assert args.cmd == "verify-audit"

    args2 = parser.parse_args(["verify-audit", "--log", "case/audit.jsonl", "--allow-unsigned"])
    assert args2.allow_unsigned is True
