import argparse
import hashlib
from pathlib import Path


SUPPORTED_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def calculate_hash(file_path, algorithm="sha256", chunk_size=8192):
    """Calculate the cryptographic hash of a file."""

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    hash_function = SUPPORTED_ALGORITHMS[algorithm]()
    
    with open(file_path, "rb") as file:
        while chunk := file.read(chunk_size):
            hash_function.update(chunk)

    return hash_function.hexdigest()


def verify_hash(file_path, expected_hash, algorithm="sha256"):
    """Verify a file against an expected hash."""

    actual_hash = calculate_hash(file_path, algorithm)

    return actual_hash.lower() == expected_hash.lower()


def main():
    parser = argparse.ArgumentParser(
        description="Calculate and verify file hashes."
    )

    parser.add_argument(
        "--file",
        required=True,
        help="Path to the file"
    )

    parser.add_argument(
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS.keys(),
        default="sha256",
        help="Hash algorithm"
    )

    parser.add_argument(
        "--check",
        help="Expected hash for verification"
    )

    args = parser.parse_args()

    file_path = Path(args.file)

    if not file_path.is_file():
        print(f"Error: File not found: {file_path}")
        return 1

    try:
        file_hash = calculate_hash(
            file_path,
            args.algorithm
        )

        print(f"File: {file_path}")
        print(f"Algorithm: {args.algorithm.upper()}")
        print(f"Hash: {file_hash}")

        if args.check:
            if verify_hash(
                file_path,
                args.check,
                args.algorithm
            ):
                print("Result: HASH MATCH")
                return 0

            print("Result: HASH MISMATCH")
            return 1

        return 0

    except ValueError as error:
        print(f"Error: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())