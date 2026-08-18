from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tools.__main__ import (
    build_parser,
    fim_baseline_command,
    fim_check_command,
    hash_command,
    main,
    scan_command,
    subnet_command,
)

# ============================================================
# build_parser()
# ============================================================


def test_parser_scan_command():
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
    assert args.start_port == 1
    assert args.end_port == 1024
    assert args.timeout == 0.5
    assert args.workers == 100
    assert args.output is None
    assert args.config is None


def test_parser_scan_custom_options():
    parser = build_parser()

    args = parser.parse_args(
        [
            "scan",
            "--target",
            "192.168.1.10",
            "--start-port",
            "20",
            "--end-port",
            "100",
            "--timeout",
            "1.5",
            "--workers",
            "20",
            "--output",
            "report.json",
            "--config",
            "config.json",
        ]
    )

    assert args.command == "scan"
    assert args.target == "192.168.1.10"
    assert args.start_port == 20
    assert args.end_port == 100
    assert args.timeout == 1.5
    assert args.workers == 20
    assert args.output == "report.json"
    assert args.config == "config.json"


def test_parser_subnet_command():
    parser = build_parser()

    args = parser.parse_args(
        [
            "subnet",
            "--network",
            "192.168.1.0/24",
        ]
    )

    assert args.command == "subnet"
    assert args.network == "192.168.1.0/24"
    assert args.timeout == 1
    assert args.workers == 100


def test_parser_subnet_custom_options():
    parser = build_parser()

    args = parser.parse_args(
        [
            "subnet",
            "--network",
            "10.0.0.0/24",
            "--timeout",
            "2.5",
            "--workers",
            "25",
        ]
    )

    assert args.command == "subnet"
    assert args.network == "10.0.0.0/24"
    assert args.timeout == 2.5
    assert args.workers == 25


def test_parser_hash_command():
    parser = build_parser()

    args = parser.parse_args(
        [
            "hash",
            "--file",
            "test.txt",
        ]
    )

    assert args.command == "hash"
    assert args.file == "test.txt"
    assert args.algorithm == "sha256"


def test_parser_hash_custom_algorithm():
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

    assert args.command == "hash"
    assert args.file == "test.txt"
    assert args.algorithm == "sha512"


def test_parser_fim_baseline():
    parser = build_parser()

    args = parser.parse_args(
        [
            "fim",
            "baseline",
            "--directory",
            "test_dir",
        ]
    )

    assert args.command == "fim"
    assert args.fim_command == "baseline"
    assert args.directory == "test_dir"
    assert args.output == "baseline.json"


def test_parser_fim_baseline_custom_output():
    parser = build_parser()

    args = parser.parse_args(
        [
            "fim",
            "baseline",
            "--directory",
            "test_dir",
            "--output",
            "custom.json",
        ]
    )

    assert args.command == "fim"
    assert args.fim_command == "baseline"
    assert args.directory == "test_dir"
    assert args.output == "custom.json"


def test_parser_fim_check():
    parser = build_parser()

    args = parser.parse_args(
        [
            "fim",
            "check",
            "--directory",
            "test_dir",
        ]
    )

    assert args.command == "fim"
    assert args.fim_command == "check"
    assert args.directory == "test_dir"
    assert args.baseline == "baseline.json"


def test_parser_fim_check_custom_baseline():
    parser = build_parser()

    args = parser.parse_args(
        [
            "fim",
            "check",
            "--directory",
            "test_dir",
            "--baseline",
            "custom.json",
        ]
    )

    assert args.command == "fim"
    assert args.fim_command == "check"
    assert args.directory == "test_dir"
    assert args.baseline == "custom.json"


def test_parser_requires_command():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_requires_scan_target():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["scan"])


def test_parser_requires_subnet_network():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["subnet"])


def test_parser_requires_fim_subcommand():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "fim",
            ]
        )


# ============================================================
# hash_command()
# ============================================================


def test_hash_command(capsys):
    args = SimpleNamespace(
        file="test.txt",
        algorithm="sha256",
    )

    with patch(
        "tools.__main__.calculate_hash",
        return_value="abcdef123456",
    ) as mock_hash:
        result = hash_command(args)

    captured = capsys.readouterr()

    assert result is None

    mock_hash.assert_called_once_with(
        "test.txt",
        "sha256",
    )

    assert "File: test.txt" in captured.out
    assert "Algorithm: SHA256" in captured.out
    assert "Hash: abcdef123456" in captured.out


def test_hash_command_sha512(capsys):
    args = SimpleNamespace(
        file="example.bin",
        algorithm="sha512",
    )

    with patch(
        "tools.__main__.calculate_hash",
        return_value="1234567890",
    ):
        hash_command(args)

    captured = capsys.readouterr()

    assert "File: example.bin" in captured.out
    assert "Algorithm: SHA512" in captured.out
    assert "Hash: 1234567890" in captured.out


# ============================================================
# fim_baseline_command()
# ============================================================


def test_fim_baseline_command(capsys):
    args = SimpleNamespace(
        directory="test_dir",
        output="baseline.json",
    )

    baseline = {
        "test.txt": "abcdef123456",
        "config.ini": "123456abcdef",
    }

    with patch(
        "tools.__main__.create_baseline",
        return_value=baseline,
    ) as mock_create, patch(
        "tools.__main__.save_baseline",
    ) as mock_save:
        result = fim_baseline_command(args)

    captured = capsys.readouterr()

    assert result is None

    mock_create.assert_called_once_with(
        "test_dir",
    )

    mock_save.assert_called_once_with(
        baseline,
        "baseline.json",
    )

    assert "Baseline created: baseline.json" in captured.out
    assert "Files monitored: 2" in captured.out


def test_fim_baseline_command_empty(capsys):
    args = SimpleNamespace(
        directory="empty_dir",
        output="empty.json",
    )

    with patch(
        "tools.__main__.create_baseline",
        return_value={},
    ), patch(
        "tools.__main__.save_baseline",
    ):
        fim_baseline_command(args)

    captured = capsys.readouterr()

    assert "Baseline created: empty.json" in captured.out
    assert "Files monitored: 0" in captured.out


# ============================================================
# fim_check_command()
# ============================================================


def test_fim_check_integrity_ok(capsys):
    args = SimpleNamespace(
        directory="test_dir",
        baseline="baseline.json",
    )

    result_data = {
        "added": [],
        "deleted": [],
        "modified": [],
    }

    with patch(
        "tools.__main__.load_baseline",
        return_value={"test.txt": "hash"},
    ) as mock_load, patch(
        "tools.__main__.check_integrity",
        return_value=result_data,
    ) as mock_check:
        result = fim_check_command(args)

    captured = capsys.readouterr()

    assert result == 0

    mock_load.assert_called_once_with(
        "baseline.json",
    )

    mock_check.assert_called_once_with(
        "test_dir",
        {"test.txt": "hash"},
    )

    assert "File Integrity Check" in captured.out
    assert "Added:    0" in captured.out
    assert "Deleted:  0" in captured.out
    assert "Modified: 0" in captured.out
    assert "STATUS: INTEGRITY OK" in captured.out


def test_fim_check_added_files(capsys):
    args = SimpleNamespace(
        directory="test_dir",
        baseline="baseline.json",
    )

    result_data = {
        "added": [
            "new_file.txt",
            "another.txt",
        ],
        "deleted": [],
        "modified": [],
    }

    with patch(
        "tools.__main__.load_baseline",
        return_value={},
    ), patch(
        "tools.__main__.check_integrity",
        return_value=result_data,
    ):
        result = fim_check_command(args)

    captured = capsys.readouterr()

    assert result == 1

    assert "Added:    2" in captured.out
    assert "Deleted:  0" in captured.out
    assert "Modified: 0" in captured.out

    assert "Added files:" in captured.out
    assert "+ new_file.txt" in captured.out
    assert "+ another.txt" in captured.out

    assert "STATUS: INTEGRITY CHECK FAILED" in captured.out


def test_fim_check_deleted_files(capsys):
    args = SimpleNamespace(
        directory="test_dir",
        baseline="baseline.json",
    )

    result_data = {
        "added": [],
        "deleted": [
            "old_file.txt",
        ],
        "modified": [],
    }

    with patch(
        "tools.__main__.load_baseline",
        return_value={},
    ), patch(
        "tools.__main__.check_integrity",
        return_value=result_data,
    ):
        result = fim_check_command(args)

    captured = capsys.readouterr()

    assert result == 1

    assert "Deleted:  1" in captured.out
    assert "Deleted files:" in captured.out
    assert "- old_file.txt" in captured.out
    assert "STATUS: INTEGRITY CHECK FAILED" in captured.out


def test_fim_check_modified_files(capsys):
    args = SimpleNamespace(
        directory="test_dir",
        baseline="baseline.json",
    )

    result_data = {
        "added": [],
        "deleted": [],
        "modified": [
            "config.ini",
            "settings.json",
        ],
    }

    with patch(
        "tools.__main__.load_baseline",
        return_value={},
    ), patch(
        "tools.__main__.check_integrity",
        return_value=result_data,
    ):
        result = fim_check_command(args)

    captured = capsys.readouterr()

    assert result == 1

    assert "Modified: 2" in captured.out
    assert "Modified files:" in captured.out
    assert "! config.ini" in captured.out
    assert "! settings.json" in captured.out
    assert "STATUS: INTEGRITY CHECK FAILED" in captured.out


def test_fim_check_all_changes(capsys):
    args = SimpleNamespace(
        directory="test_dir",
        baseline="baseline.json",
    )

    result_data = {
        "added": ["new.txt"],
        "deleted": ["old.txt"],
        "modified": ["changed.txt"],
    }

    with patch(
        "tools.__main__.load_baseline",
        return_value={},
    ), patch(
        "tools.__main__.check_integrity",
        return_value=result_data,
    ):
        result = fim_check_command(args)

    captured = capsys.readouterr()

    assert result == 1

    assert "Added:    1" in captured.out
    assert "Deleted:  1" in captured.out
    assert "Modified: 1" in captured.out

    assert "Added files:" in captured.out
    assert "Deleted files:" in captured.out
    assert "Modified files:" in captured.out

    assert "STATUS: INTEGRITY CHECK FAILED" in captured.out


# ============================================================
# subnet_command()
# ============================================================


def test_subnet_command_success(capsys):
    args = SimpleNamespace(
        network="192.168.1.0/30",
        timeout=1,
        workers=10,
    )

    with patch(
        "tools.subnet_scanner.scan_subnet",
        return_value=[
            "192.168.1.1",
            "192.168.1.2",
        ],
    ) as mock_scan, patch(
        "time.perf_counter",
        side_effect=[1.0, 1.5],
    ):
        result = subnet_command(args)

    captured = capsys.readouterr()

    assert result == 0

    mock_scan.assert_called_once_with(
        "192.168.1.0/30",
        1,
        10,
    )

    assert "PYTHON SECURITY TOOLS" in captured.out
    assert "SUBNET SCANNER" in captured.out
    assert "Network: 192.168.1.0/30" in captured.out
    assert "Hosts: 2" in captured.out
    assert "Workers: 10" in captured.out
    assert "Starting subnet scan..." in captured.out

    assert "[+] 192.168.1.1" in captured.out
    assert "[+] 192.168.1.2" in captured.out
    assert "ONLINE" in captured.out

    assert "Subnet scan completed." in captured.out
    assert "Online hosts: 2" in captured.out
    assert "Offline hosts: 0" in captured.out
    assert "Scan time: 0.50 seconds" in captured.out


def test_subnet_command_partial_hosts(capsys):
    args = SimpleNamespace(
        network="192.168.1.0/29",
        timeout=0.5,
        workers=5,
    )

    with patch(
        "tools.subnet_scanner.scan_subnet",
        return_value=[
            "192.168.1.1",
            "192.168.1.5",
        ],
    ), patch(
        "time.perf_counter",
        side_effect=[10.0, 10.25],
    ):
        result = subnet_command(args)

    captured = capsys.readouterr()

    assert result == 0
    assert "Hosts: 6" in captured.out
    assert "Online hosts: 2" in captured.out
    assert "Offline hosts: 4" in captured.out


def test_subnet_command_invalid_network(capsys):
    args = SimpleNamespace(
        network="not-a-network",
        timeout=1,
        workers=10,
    )

    result = subnet_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Invalid network: not-a-network" in captured.out


def test_subnet_command_invalid_workers(capsys):
    args = SimpleNamespace(
        network="192.168.1.0/24",
        timeout=1,
        workers=0,
    )

    result = subnet_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Invalid number of workers: 0" in captured.out


def test_subnet_command_scan_error(capsys):
    args = SimpleNamespace(
        network="192.168.1.0/30",
        timeout=1,
        workers=10,
    )

    with patch(
        "tools.subnet_scanner.scan_subnet",
        side_effect=ValueError("Invalid scanner configuration"),
    ):
        result = subnet_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Invalid scanner configuration" in captured.out


# ============================================================
# scan_command()
# ============================================================


def create_scan_args(
    target="127.0.0.1",
    start_port=20,
    end_port=22,
    timeout=0.5,
    workers=10,
    output=None,
    config=None,
):
    return SimpleNamespace(
        target=target,
        start_port=start_port,
        end_port=end_port,
        timeout=timeout,
        workers=workers,
        output=output,
        config=config,
    )


def test_scan_command_success(capsys):
    args = create_scan_args()

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.__main__.run_scan",
        return_value=[22],
    ) as mock_scan, patch(
        "tools.__main__.get_service_name",
        return_value="SSH",
    ), patch(
        "tools.__main__.get_banner",
        return_value="SSH-2.0-OpenSSH",
    ), patch(
        "tools.__main__.detect_service",
        return_value="SSH",
    ), patch(
        "tools.__main__.check_services",
        return_value=[],
    ), patch(
        "tools.__main__.time.perf_counter",
        side_effect=[1.0, 1.5],
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 0

    mock_scan.assert_called_once_with(
        "127.0.0.1",
        20,
        22,
        0.5,
        10,
    )

    assert "PYTHON SECURITY TOOLS" in captured.out
    assert "PORT SCANNER" in captured.out
    assert "Target: 127.0.0.1" in captured.out
    assert "Resolved IP: 127.0.0.1" in captured.out
    assert "Ports: 20-22" in captured.out
    assert "Workers: 10" in captured.out
    assert "Starting scan..." in captured.out
    assert "Open ports: 1" in captured.out
    assert "Closed ports: 2" in captured.out
    assert "Scan completed." in captured.out


def test_scan_command_detected_service_replaces_default(
    capsys,
):
    args = create_scan_args()

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="192.168.1.10",
    ), patch(
        "tools.__main__.run_scan",
        return_value=[80],
    ), patch(
        "tools.__main__.get_service_name",
        return_value="HTTP",
    ) as mock_service, patch(
        "tools.__main__.get_banner",
        return_value="Apache/2.4.58",
    ), patch(
        "tools.__main__.detect_service",
        return_value="Apache",
    ) as mock_detect, patch(
        "tools.__main__.check_services",
        return_value=[],
    ), patch(
        "tools.__main__.time.perf_counter",
        side_effect=[1.0, 1.2],
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 0
    assert mock_service.called
    assert mock_detect.called
    assert "Apache" in captured.out


def test_scan_command_unknown_detected_service(
    capsys,
):
    args = create_scan_args()

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.__main__.run_scan",
        return_value=[80],
    ), patch(
        "tools.__main__.get_service_name",
        return_value="HTTP",
    ), patch(
        "tools.__main__.get_banner",
        return_value="Unknown banner",
    ), patch(
        "tools.__main__.detect_service",
        return_value="Unknown",
    ), patch(
        "tools.__main__.check_services",
        return_value=[],
    ), patch(
        "tools.__main__.time.perf_counter",
        side_effect=[1.0, 1.1],
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 0
    assert "HTTP" in captured.out
    assert "Unknown banner" in captured.out


def test_scan_command_empty_banner(
    capsys,
):
    args = create_scan_args()

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.__main__.run_scan",
        return_value=[80],
    ), patch(
        "tools.__main__.get_service_name",
        return_value="HTTP",
    ), patch(
        "tools.__main__.get_banner",
        return_value="",
    ), patch(
        "tools.__main__.detect_service",
        return_value="Unknown",
    ), patch(
        "tools.__main__.check_services",
        return_value=[],
    ), patch(
        "tools.__main__.time.perf_counter",
        side_effect=[1.0, 1.1],
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 0
    assert "HTTP" in captured.out


def test_scan_command_security_findings(
    capsys,
):
    args = create_scan_args()

    findings = [
        {
            "risk": "HIGH",
            "service": "FTP",
            "port": 21,
            "message": "FTP service detected",
        },
        {
            "risk": "MEDIUM",
            "service": "HTTP",
            "port": 80,
            "message": "HTTP service detected",
        },
    ]

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.__main__.run_scan",
        return_value=[21, 80],
    ), patch(
        "tools.__main__.get_service_name",
        side_effect=["FTP", "HTTP"],
    ), patch(
        "tools.__main__.get_banner",
        side_effect=["FTP banner", "HTTP banner"],
    ), patch(
        "tools.__main__.detect_service",
        return_value="Unknown",
    ), patch(
        "tools.__main__.check_services",
        return_value=findings,
    ), patch(
        "tools.__main__.time.perf_counter",
        side_effect=[1.0, 1.2],
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 0

    assert "Security Assessment" in captured.out
    assert "[HIGH] FTP on port 21" in captured.out
    assert "FTP service detected" in captured.out
    assert "[MEDIUM] HTTP on port 80" in captured.out
    assert "HTTP service detected" in captured.out


def test_scan_command_save_report(
    capsys,
):
    args = create_scan_args(
        output="report.json",
    )

    findings = [
        {
            "risk": "LOW",
            "service": "HTTP",
            "port": 80,
            "message": "Test finding",
        }
    ]

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.__main__.run_scan",
        return_value=[80],
    ), patch(
        "tools.__main__.get_service_name",
        return_value="HTTP",
    ), patch(
        "tools.__main__.get_banner",
        return_value="Apache",
    ), patch(
        "tools.__main__.detect_service",
        return_value="Apache",
    ), patch(
        "tools.__main__.check_services",
        return_value=findings,
    ), patch(
        "tools.__main__.save_scan_report",
    ) as mock_report, patch(
        "tools.__main__.time.perf_counter",
        side_effect=[1.0, 1.5],
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 0

    mock_report.assert_called_once()

    report_args = mock_report.call_args.args

    assert report_args[0] == "report.json"
    assert report_args[1] == "127.0.0.1"
    assert report_args[2] == 20
    assert report_args[3] == 22

    assert "Report saved: report.json" in captured.out


def test_scan_command_dns_error(capsys):
    args = create_scan_args(
        target="invalid-host",
    )

    with patch(
        "tools.__main__.socket.gethostbyname",
        side_effect=__import__("socket").gaierror(),
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Could not resolve target." in captured.out


def test_scan_command_invalid_port(capsys):
    args = create_scan_args(
        start_port=0,
        end_port=100,
    )

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Ports must be between 1 and 65535." in captured.out


def test_scan_command_end_port_too_large(capsys):
    args = create_scan_args(
        start_port=1,
        end_port=65536,
    )

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Ports must be between 1 and 65535." in captured.out


def test_scan_command_start_greater_than_end(
    capsys,
):
    args = create_scan_args(
        start_port=100,
        end_port=50,
    )

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert (
        "[!] Start port cannot be greater than end port."
        in captured.out
    )


def test_scan_command_invalid_workers(capsys):
    args = create_scan_args(
        workers=0,
    )

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Workers must be greater than 0." in captured.out


def test_scan_command_run_scan_error(capsys):
    args = create_scan_args()

    with patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.__main__.run_scan",
        side_effect=ValueError("Scanner configuration error"),
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Scanner configuration error" in captured.out


# ============================================================
# scan_command() + configuration
# ============================================================


def test_scan_command_with_config(capsys):
    args = create_scan_args(
        start_port=1,
        end_port=10,
        timeout=0.5,
        workers=5,
        config="config.json",
    )

    config = {
        "scanner": {
            "start_port": 100,
            "end_port": 200,
            "timeout": 1.5,
            "workers": 25,
        }
    }

    scan_config = {
        "start_port": 100,
        "end_port": 200,
        "timeout": 1.5,
        "workers": 25,
    }

    with patch(
        "tools.__main__.load_config",
        return_value=config,
    ) as mock_load, patch(
        "tools.__main__.get_scan_config",
        return_value=scan_config,
    ) as mock_get, patch(
        "tools.__main__.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.__main__.run_scan",
        return_value=[],
    ) as mock_scan, patch(
        "tools.__main__.check_services",
        return_value=[],
    ), patch(
        "tools.__main__.time.perf_counter",
        side_effect=[1.0, 1.2],
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 0

    mock_load.assert_called_once_with(
        "config.json",
    )

    mock_get.assert_called_once_with(
        config,
    )

    mock_scan.assert_called_once_with(
        "127.0.0.1",
        100,
        200,
        1.5,
        25,
    )

    assert "Ports: 100-200" in captured.out
    assert "Workers: 25" in captured.out


def test_scan_command_config_file_not_found(
    capsys,
):
    args = create_scan_args(
        config="missing.json",
    )

    with patch(
        "tools.__main__.load_config",
        side_effect=FileNotFoundError(
            "Configuration file not found"
        ),
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Configuration error:" in captured.out
    assert "Configuration file not found" in captured.out


def test_scan_command_invalid_json_config(
    capsys,
):
    import json

    args = create_scan_args(
        config="broken.json",
    )

    with patch(
        "tools.__main__.load_config",
        side_effect=json.JSONDecodeError(
            "Invalid JSON",
            "",
            0,
        ),
    ):
        result = scan_command(args)

    captured = capsys.readouterr()

    assert result == 1
    assert "[!] Configuration error:" in captured.out


# ============================================================
# main()
# ============================================================


def test_main_dispatches_hash(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "tools",
            "hash",
            "--file",
            "test.txt",
        ],
    )

    with patch(
        "tools.__main__.calculate_hash",
        return_value="abcdef",
    ) as mock_hash:
        result = main()

    assert result is None
    mock_hash.assert_called_once_with(
        "test.txt",
        "sha256",
    )


def test_main_dispatches_subnet(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "tools",
            "subnet",
            "--network",
            "192.168.1.0/30",
        ],
    )

    with patch(
        "tools.__main__.scan_subnet",
        return_value=[],
    ), patch(
        "time.perf_counter",
        side_effect=[1.0, 1.1],
    ):
        result = main()

    assert result == 0


def test_main_dispatches_fim_baseline(
    monkeypatch,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "tools",
            "fim",
            "baseline",
            "--directory",
            "test_dir",
        ],
    )

    with patch(
        "tools.__main__.create_baseline",
        return_value={},
    ), patch(
        "tools.__main__.save_baseline",
    ):
        result = main()

    assert result is None


def test_main_dispatches_fim_check(
    monkeypatch,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "tools",
            "fim",
            "check",
            "--directory",
            "test_dir",
        ],
    )

    with patch(
        "tools.__main__.load_baseline",
        return_value={},
    ), patch(
        "tools.__main__.check_integrity",
        return_value={
            "added": [],
            "deleted": [],
            "modified": [],
        },
    ):
        result = main()

    assert result == 0