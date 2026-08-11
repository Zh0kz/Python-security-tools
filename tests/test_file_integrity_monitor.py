from tools.file_integrity_monitor import (
    create_baseline,
    check_integrity,
)


def test_create_baseline(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    baseline = create_baseline(tmp_path)

    assert "test.txt" in baseline


def test_integrity_ok(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    baseline = create_baseline(tmp_path)

    result = check_integrity(
        tmp_path,
        baseline
    )

    assert result["added"] == []
    assert result["deleted"] == []
    assert result["modified"] == []


def test_detect_modified_file(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Original")

    baseline = create_baseline(tmp_path)

    test_file.write_text("Modified")

    result = check_integrity(
        tmp_path,
        baseline
    )

    assert result["modified"] == ["test.txt"]


def test_detect_added_file(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Original")

    baseline = create_baseline(tmp_path)

    added_file = tmp_path / "malware.txt"
    added_file.write_text("Suspicious file")

    result = check_integrity(
        tmp_path,
        baseline
    )

    assert result["added"] == ["malware.txt"]


def test_detect_deleted_file(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Original")

    baseline = create_baseline(tmp_path)

    test_file.unlink()

    result = check_integrity(
        tmp_path,
        baseline
    )

    assert result["deleted"] == ["test.txt"]