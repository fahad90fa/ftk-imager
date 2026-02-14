from forensic_imager.cli import build_parser


def test_new_commands_present() -> None:
    parser = build_parser()

    args = parser.parse_args(["convert", "--input", "a.dd", "--output", "b.e01", "--to-format", "e01"])
    assert args.cmd == "convert"

    args = parser.parse_args(["network-acquire", "--host", "lab", "--source", "/dev/sdb", "--output-image", "o.dd", "--hash-file", "o.hash"])
    assert args.cmd == "network-acquire"

    args = parser.parse_args(["acquire-e01", "--source", "/dev/sdb", "--output-prefix", "evidence", "--case-number", "C", "--evidence-number", "E", "--examiner", "X"])
    assert args.cmd == "acquire-e01"
