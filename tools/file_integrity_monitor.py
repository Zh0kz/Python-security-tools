import argparse
import json
from pathlib import Path

from tools.hash_checker import calculate_hash


DEFAULT_ALGORITHM = "sha256"


def create_baseline(directory):
    """
    Create a SHA-256 baseline for all files in a directory.
    """

    directory = Path(directory)

    if not directory.is_dir():
        raise ValueError(f"Directory not found: {directory}")

    baseline = {}

    for file_path in sorted(directory.rglob("*")):
        if not file_path.is_file():
            continue

        file_hash = calculate_hash(
            file_path,
            DEFAULT_ALGORITHM
        )

        relative_path = file_path.relative_to(directory)

        baseline[str(relative_path)] = file_hash

    return baseline


def save_baseline(baseline, baseline_path):
    """
    Save baseline hashes to a JSON file.
    """

    baseline_path = Path(baseline_path)

    with baseline_path.open("w", encoding="utf-8") as file:
        json.dump(
            baseline,
            file,
            indent=4,
            sort_keys=True
        )


def load_baseline(baseline_path):
    """
    Load baseline hashes from a JSON file.
    """

    baseline_path = Path(baseline_path)

    if not baseline_path.is_file():
        raise ValueError(
            f"Baseline file not found: {baseline_path}"
        )

    with baseline_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def check_integrity(directory, baseline):
    """
    Compare current file hashes with the baseline.
    """

    directory = Path(directory)

    if not directory.is_dir():
        raise ValueError(f"Directory not found: {directory}")

    current_files = {}

    for file_path in sorted(directory.rglob("*")):
        if not file_path.is_file():
            continue

        relative_path = str(file_path.relative_to(directory))

        current_files[relative_path] = calculate_hash(
            file_path,
            DEFAULT_ALGORITHM
        )

    added = sorted(
        set(current_files) - set(baseline)
    )

    deleted = sorted(
        set(baseline) - set(current_files)
    )

    modified = sorted(
        path
        for path in set(current_files) & set(baseline)
        if current_files[path] != baseline[path]
    )

    return {
        "added": added,
        "deleted": deleted,
        "modified": modified,
    }


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    baseline_parser = subparsers.add_parser(
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

    check_parser = subparsers.add_parser(
        "check",
        help="Check directory integrity"
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

    args = parser.parse_args()

    try:
        if args.command == "baseline":
            baseline = create_baseline(
                args.directory
            )

            save_baseline(
                baseline,
                args.output
            )

            print(
                f"Baseline created: {args.output}"
            )

            print(
                f"Files monitored: {len(baseline)}"
            )

            return 0

        if args.command == "check":
            baseline = load_baseline(
                args.baseline
            )

            result = check_integrity(
                args.directory,
                baseline
            )

            print("File Integrity Check")
            print("=" * 40)

            print(
                f"Added:    {len(result['added'])}"
            )

            print(
                f"Deleted:  {len(result['deleted'])}"
            )

            print(
                f"Modified: {len(result['modified'])}"
            )

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

    except ValueError as error:
        print(f"Error: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())