from forensic_imager.cli import build_parser


def test_export_file_command_present() -> None:
    parser = build_parser()
    args = parser.parse_args([
        "export-file",
        "--image",
        "img.dd",
        "--start-sector",
        "2048",
        "--inode",
        "5-128-1",
        "--output",
        "out.bin",
    ])
    assert args.cmd == "export-file"
    assert args.start_sector == 2048
