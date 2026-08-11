import hashlib

from tools.hash_checker import calculate_hash, verify_hash


def test_sha256(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    expected_hash = hashlib.sha256(
        b"Hello Security World!"
    ).hexdigest()

    assert calculate_hash(
        test_file,
        "sha256"
    ) == expected_hash


def test_sha512(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    expected_hash = hashlib.sha512(
        b"Hello Security World!"
    ).hexdigest()

    assert calculate_hash(
        test_file,
        "sha512"
    ) == expected_hash


def test_hash_verification_success(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    expected_hash = hashlib.sha256(
        b"Hello Security World!"
    ).hexdigest()

    assert verify_hash(
        test_file,
        expected_hash,
        "sha256"
    )


def test_hash_verification_failure(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    wrong_hash = "0" * 64

    assert not verify_hash(
        test_file,
        wrong_hash,
        "sha256"
    )


def test_case_insensitive_hash(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    expected_hash = hashlib.sha256(
        b"Hello Security World!"
    ).hexdigest()

    assert verify_hash(
        test_file,
        expected_hash.upper(),
        "sha256"
    )