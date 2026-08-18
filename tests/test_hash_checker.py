import hashlib

import pytest

from tools.hash_checker import calculate_hash, main, verify_hash


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


def test_md5(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    expected_hash = hashlib.md5(
        b"Hello Security World!"
    ).hexdigest()

    assert calculate_hash(
        test_file,
        "md5"
    ) == expected_hash


def test_unsupported_algorithm(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    with pytest.raises(
        ValueError,
        match="Unsupported algorithm: sha1"
    ):
        calculate_hash(
            test_file,
            "sha1"
        )


def test_large_file(tmp_path):
    test_file = tmp_path / "large.txt"

    content = b"A" * 20000
    test_file.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()

    assert calculate_hash(
        test_file,
        "sha256"
    ) == expected_hash


def test_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        calculate_hash(
            "nonexistent_file.txt",
            "sha256"
        )


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


def test_main_file_not_found(tmp_path, monkeypatch, capsys):
    missing_file = tmp_path / "missing.txt"

    monkeypatch.setattr(
        "sys.argv",
        [
            "hash_checker",
            "--file",
            str(missing_file),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "File not found" in captured.out


def test_main_hash_only(tmp_path, monkeypatch, capsys):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    expected_hash = hashlib.sha256(
        b"Hello Security World!"
    ).hexdigest()

    monkeypatch.setattr(
        "sys.argv",
        [
            "hash_checker",
            "--file",
            str(test_file),
            "--algorithm",
            "sha256",
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 0
    assert f"File: {test_file}" in captured.out
    assert "Algorithm: SHA256" in captured.out
    assert f"Hash: {expected_hash}" in captured.out


def test_main_hash_match(tmp_path, monkeypatch, capsys):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    expected_hash = hashlib.sha256(
        b"Hello Security World!"
    ).hexdigest()

    monkeypatch.setattr(
        "sys.argv",
        [
            "hash_checker",
            "--file",
            str(test_file),
            "--algorithm",
            "sha256",
            "--check",
            expected_hash,
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 0
    assert "Result: HASH MATCH" in captured.out


def test_main_hash_mismatch(tmp_path, monkeypatch, capsys):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    wrong_hash = "0" * 64

    monkeypatch.setattr(
        "sys.argv",
        [
            "hash_checker",
            "--file",
            str(test_file),
            "--algorithm",
            "sha256",
            "--check",
            wrong_hash,
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "Result: HASH MISMATCH" in captured.out


def test_main_unsupported_algorithm(tmp_path, monkeypatch, capsys):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    monkeypatch.setattr(
        "sys.argv",
        [
            "hash_checker",
            "--file",
            str(test_file),
            "--algorithm",
            "sha256",
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 0
    assert "Algorithm: SHA256" in captured.out