import json

import pytest

from tools.file_integrity_monitor import (
    check_integrity,
    create_baseline,
    load_baseline,
    main,
    save_baseline,
)


def test_create_baseline(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    baseline = create_baseline(tmp_path)

    assert "test.txt" in baseline
    assert len(baseline) == 1


def test_create_baseline_nested_directory(tmp_path):
    nested_dir = tmp_path / "subdir"
    nested_dir.mkdir()

    test_file = nested_dir / "test.txt"
    test_file.write_text("Nested file")

    baseline = create_baseline(tmp_path)

    assert (
        "subdir\\test.txt" in baseline
        or "subdir/test.txt" in baseline
    )


def test_create_baseline_ignores_directories(tmp_path):
    nested_dir = tmp_path / "empty_dir"
    nested_dir.mkdir()

    baseline = create_baseline(tmp_path)

    assert baseline == {}


def test_create_baseline_invalid_directory(tmp_path):
    missing_dir = tmp_path / "missing"

    with pytest.raises(
        ValueError,
        match="Directory not found",
    ):
        create_baseline(missing_dir)


def test_save_and_load_baseline(tmp_path):
    baseline = {
        "test.txt": "abc123",
        "config.json": "def456",
    }

    baseline_file = tmp_path / "baseline.json"

    save_baseline(
        baseline,
        baseline_file,
    )

    assert baseline_file.exists()

    loaded = load_baseline(baseline_file)

    assert loaded == baseline


def test_saved_baseline_is_valid_json(tmp_path):
    baseline = {
        "test.txt": "abc123",
    }

    baseline_file = tmp_path / "baseline.json"

    save_baseline(
        baseline,
        baseline_file,
    )

    with baseline_file.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    assert data == baseline


def test_load_baseline_not_found(tmp_path):
    baseline_file = tmp_path / "missing.json"

    with pytest.raises(
        ValueError,
        match="Baseline file not found",
    ):
        load_baseline(baseline_file)


def test_integrity_ok(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    baseline = create_baseline(tmp_path)

    result = check_integrity(
        tmp_path,
        baseline,
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
        baseline,
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
        baseline,
    )

    assert result["added"] == ["malware.txt"]


def test_detect_deleted_file(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Original")

    baseline = create_baseline(tmp_path)

    test_file.unlink()

    result = check_integrity(
        tmp_path,
        baseline,
    )

    assert result["deleted"] == ["test.txt"]


def test_detect_multiple_changes(tmp_path):
    original_file = tmp_path / "original.txt"
    original_file.write_text("Original")

    deleted_file = tmp_path / "deleted.txt"
    deleted_file.write_text("Delete me")

    baseline = create_baseline(tmp_path)

    original_file.write_text("Modified")
    deleted_file.unlink()

    added_file = tmp_path / "added.txt"
    added_file.write_text("New file")

    result = check_integrity(
        tmp_path,
        baseline,
    )

    assert result["added"] == ["added.txt"]
    assert result["deleted"] == ["deleted.txt"]
    assert result["modified"] == ["original.txt"]


def test_check_integrity_invalid_directory(tmp_path):
    missing_dir = tmp_path / "missing"

    with pytest.raises(
        ValueError,
        match="Directory not found",
    ):
        check_integrity(
            missing_dir,
            {},
        )


def test_main_baseline(tmp_path, monkeypatch, capsys):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    baseline_file = tmp_path / "baseline.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "file_integrity_monitor",
            "baseline",
            "--directory",
            str(tmp_path),
            "--output",
            str(baseline_file),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 0
    assert baseline_file.exists()
    assert "Baseline created" in captured.out
    assert "Files monitored: 1" in captured.out


def test_main_baseline_default_output(
    tmp_path,
    monkeypatch,
    capsys,
):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    monkeypatch.chdir(tmp_path)

    monkeypatch.setattr(
        "sys.argv",
        [
            "file_integrity_monitor",
            "baseline",
            "--directory",
            str(tmp_path),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 0
    assert "Baseline created: baseline.json" in captured.out
    assert (tmp_path / "baseline.json").exists()


def test_main_check_integrity_ok(
    tmp_path,
    monkeypatch,
    capsys,
):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello Security World!")

    # Baseline находится вне директории,
    # которую мы проверяем.
    baseline_file = tmp_path.parent / "baseline.json"

    baseline = create_baseline(tmp_path)

    save_baseline(
        baseline,
        baseline_file,
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "file_integrity_monitor",
            "check",
            "--directory",
            str(tmp_path),
            "--baseline",
            str(baseline_file),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 0
    assert "File Integrity Check" in captured.out
    assert "Added:    0" in captured.out
    assert "Deleted:  0" in captured.out
    assert "Modified: 0" in captured.out
    assert "STATUS: INTEGRITY OK" in captured.out


def test_main_check_integrity_failed(
    tmp_path,
    monkeypatch,
    capsys,
):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Original")

    baseline_file = tmp_path.parent / "baseline.json"

    baseline = create_baseline(tmp_path)

    save_baseline(
        baseline,
        baseline_file,
    )

    test_file.write_text("Modified")

    monkeypatch.setattr(
        "sys.argv",
        [
            "file_integrity_monitor",
            "check",
            "--directory",
            str(tmp_path),
            "--baseline",
            str(baseline_file),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "Modified: 1" in captured.out
    assert "Modified files:" in captured.out
    assert "! test.txt" in captured.out
    assert "STATUS: INTEGRITY CHECK FAILED" in captured.out


def test_main_baseline_invalid_directory(
    tmp_path,
    monkeypatch,
    capsys,
):
    missing_dir = tmp_path / "missing"

    monkeypatch.setattr(
        "sys.argv",
        [
            "file_integrity_monitor",
            "baseline",
            "--directory",
            str(missing_dir),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "Error: Directory not found" in captured.out


def test_main_check_missing_baseline(
    tmp_path,
    monkeypatch,
    capsys,
):
    baseline_file = tmp_path / "missing.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "file_integrity_monitor",
            "check",
            "--directory",
            str(tmp_path),
            "--baseline",
            str(baseline_file),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "Error: Baseline file not found" in captured.out