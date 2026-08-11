import argparse

from tools.hash_checker import calculate_hash
from tools.file_integrity_monitor import (
    create_baseline,
    save_baseline,
    load_baseline,
    check_integrity,
)


def hash_command(args):
    file_hash = calculate_hash(
        args.file,
        args.algorithm
    )

    print(f"File: {args.file}")
    print(f"Algorithm: {args.algorithm.upper()}")
    print(f"Hash: {file_hash}")


def fim_baseline_command(args):
    baseline = create_baseline(args.directory)

    save_baseline(
        baseline,
        args.output
    )

    print(f"Baseline created: {args.output}")
    print(f"Files monitored: {len(baseline)}")


def fim_check_command(args):
    baseline = load_baseline(args.baseline)

    result = check_integrity(
        args.directory,
        baseline
    )

    print("File Integrity Check")
    print("=" * 40)
    print(f"Added:    {len(result['added'])}")
    print(f"Deleted:  {len(result['deleted'])}")
    print(f"Modified: {len(result['modified'])}")

    if result["added"]:
        print("\nAdded files:")

        for path in result["added"]:
            print(f"  + {path}")

    if result["deleted"]:
        print("\nDeleted files:")

        for path in result["deleted"]:
            print(f"  - {path}")

    if result["modified"]:
        print("\nModified files:")

        for path in result["modified"]:
            print(f"  ! {path}")

    if any(result.values()):
        print("\nSTATUS: INTEGRITY CHECK FAILED")
        return 1

    print("\nSTATUS: INTEGRITY OK")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m tools",
        description="Python Security Tools"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    # ==========================
    # HASH
    # ==========================

    hash_parser = subparsers.add_parser(
        "hash",
        help="Calculate a file hash"
    )

    hash_parser.add_argument(
        "--file",
        required=True,
        help="Path to the file"
    )

    hash_parser.add_argument(
        "--algorithm",
        choices=["md5", "sha256", "sha512"],
        default="sha256",
        help="Hash algorithm"
    )

    hash_parser.set_defaults(
        func=hash_command
    )

    # ==========================
    # FIM
    # ==========================

    fim_parser = subparsers.add_parser(
        "fim",
        help="File Integrity Monitor"
    )

    fim_subparsers = fim_parser.add_subparsers(
        dest="fim_command",
        required=True
    )

    # FIM baseline

    baseline_parser = fim_subparsers.add_parser(
        "baseline",
        help="Create a file integrity baseline"
    )

    baseline_parser.add_argument(
        "--directory",
        required=True,
        help="Directory to monitor"
    )

    baseline_parser.add_argument(
        "--output",
        default="baseline.json",
        help="Baseline output file"
    )

    baseline_parser.set_defaults(
        func=fim_baseline_command
    )

    # FIM check

    check_parser = fim_subparsers.add_parser(
        "check",
        help="Check file integrity"
    )

    check_parser.add_argument(
        "--directory",
        required=True,
        help="Directory to check"
    )

    check_parser.add_argument(
        "--baseline",
        default="baseline.json",
        help="Baseline file"
    )

    check_parser.set_defaults(
        func=fim_check_command
    )

    return parser


def main():
    parser = build_parser()

    args = parser.parse_args()

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())