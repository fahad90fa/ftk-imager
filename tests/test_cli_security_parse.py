from forensic_imager.cli import build_parser


def test_security_commands_and_flags_present() -> None:
    parser = build_parser()

    enc = parser.parse_args([
        "encrypt",
        "--input",
        "a",
        "--output",
        "b",
        "--metadata-out",
        "m.json",
        "--iter-count",
        "250000",
        "--allow-weak-password",
        "--password-env",
        "FI_PASS",
    ])
    assert enc.cmd == "encrypt"
    assert enc.iter_count == 250000

    dec = parser.parse_args([
        "decrypt",
        "--input",
        "a",
        "--output",
        "b",
        "--iter-count",
        "250000",
        "--password-file",
        "pw.txt",
    ])
    assert dec.cmd == "decrypt"

    keygen = parser.parse_args(["keygen", "--output", "key.txt", "--bytes-len", "64"])
    assert keygen.cmd == "keygen"
