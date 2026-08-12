from tools.__main__ import build_parser


def test_scan_command_exists():
    parser = build_parser()

    args = parser.parse_args(
        [
            "scan",
            "--target",
            "127.0.0.1",
        ]
    )

    assert args.command == "scan"
    assert args.target == "127.0.0.1"


def test_scan_default_values():
    parser = build_parser()

    args = parser.parse_args(
        [
            "scan",
            "--target",
            "127.0.0.1",
        ]
    )

    assert args.start_port == 1
    assert args.end_port == 1024
    assert args.timeout == 0.5
    assert args.workers == 100


def test_scan_custom_values():
    parser = build_parser()

    args = parser.parse_args(
        [
            "scan",
            "--target",
            "127.0.0.1",
            "--start-port",
            "20",
            "--end-port",
            "100",
            "--timeout",
            "1.0",
            "--workers",
            "25",
        ]
    )

    assert args.start_port == 20
    assert args.end_port == 100
    assert args.timeout == 1.0
    assert args.workers == 25