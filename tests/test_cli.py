from tools.__main__ import build_parser


def test_hash_command_exists():
    parser = build_parser()

    args = parser.parse_args(
        ["hash", "--file", "test.txt"]
    )

    assert args.command == "hash"
    assert args.algorithm == "sha256"


def test_sha512_option():
    parser = build_parser()

    args = parser.parse_args(
        [
            "hash",
            "--file",
            "test.txt",
            "--algorithm",
            "sha512",
        ]
    )

    assert args.algorithm == "sha512"


def test_fim_baseline_command():
    parser = build_parser()

    args = parser.parse_args(
        [
            "fim",
            "baseline",
            "--directory",
            "test_directory",
        ]
    )

    assert args.command == "fim"
    assert args.fim_command == "baseline"


def test_fim_check_command():
    parser = build_parser()

    args = parser.parse_args(
        [
            "fim",
            "check",
            "--directory",
            "test_directory",
        ]
    )

    assert args.command == "fim"
    assert args.fim_command == "check"