from unittest.mock import MagicMock, patch

import pytest

from tools.__main__ import build_parser
from tools.port_scanner import main

# ============================================================
# Unified CLI parser
# ============================================================


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


# ============================================================
# Service detection
# ============================================================


def test_banner_service_detection():
    from tools.service_detection import detect_service

    banner = "SSH-2.0-OpenSSH_9.6"

    assert detect_service(banner) == "SSH"


# ============================================================
# port_scanner.main()
# ============================================================


def test_main_success_with_open_port(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "port_scanner",
            "--target",
            "127.0.0.1",
            "--start-port",
            "20",
            "--end-port",
            "20",
            "--timeout",
            "0.1",
            "--workers",
            "2",
        ],
    )

    mock_future = MagicMock()
    mock_future.result.return_value = (20, True)

    mock_executor = MagicMock()
    mock_executor.__enter__.return_value = mock_executor
    mock_executor.__exit__.return_value = False

    mock_executor.submit.return_value = mock_future

    with patch(
        "tools.port_scanner.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.port_scanner.ThreadPoolExecutor",
        return_value=mock_executor,
    ), patch(
        "tools.port_scanner.as_completed",
        return_value=[mock_future],
    ), patch(
        "tools.port_scanner.get_service_name",
        return_value="FTP",
    ), patch(
        "tools.port_scanner.get_banner",
        return_value="FTP Banner",
    ), patch(
        "tools.port_scanner.time.perf_counter",
        side_effect=[1.0, 1.25],
    ):
        main()

    captured = capsys.readouterr()

    assert "PYTHON SECURITY TOOLS" in captured.out
    assert "PORT SCANNER" in captured.out
    assert "Target: 127.0.0.1" in captured.out
    assert "Ports: 20-20" in captured.out
    assert "Workers: 2" in captured.out
    assert "Resolved IP: 127.0.0.1" in captured.out
    assert "Starting scan..." in captured.out
    assert "[+] 20" in captured.out
    assert "OPEN" in captured.out
    assert "FTP" in captured.out
    assert "FTP Banner" in captured.out
    assert "Scan completed." in captured.out
    assert "Open ports: 1" in captured.out
    assert "Closed ports: 0" in captured.out
    assert "Scan time: 0.25 seconds" in captured.out


def test_main_success_without_banner(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "port_scanner",
            "--target",
            "127.0.0.1",
            "--start-port",
            "80",
            "--end-port",
            "80",
        ],
    )

    mock_future = MagicMock()
    mock_future.result.return_value = (80, True)

    mock_executor = MagicMock()
    mock_executor.__enter__.return_value = mock_executor
    mock_executor.__exit__.return_value = False
    mock_executor.submit.return_value = mock_future

    with patch(
        "tools.port_scanner.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.port_scanner.ThreadPoolExecutor",
        return_value=mock_executor,
    ), patch(
        "tools.port_scanner.as_completed",
        return_value=[mock_future],
    ), patch(
        "tools.port_scanner.get_service_name",
        return_value="HTTP",
    ), patch(
        "tools.port_scanner.get_banner",
        return_value="",
    ), patch(
        "tools.port_scanner.time.perf_counter",
        side_effect=[1.0, 2.0],
    ):
        main()

    captured = capsys.readouterr()

    assert "[+] 80" in captured.out
    assert "HTTP" in captured.out
    assert "OPEN" in captured.out
    assert "Open ports: 1" in captured.out
    assert "Closed ports: 0" in captured.out


def test_main_no_open_ports(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "port_scanner",
            "--target",
            "127.0.0.1",
            "--start-port",
            "20",
            "--end-port",
            "22",
        ],
    )

    futures = []

    for port in range(20, 23):
        future = MagicMock()
        future.result.return_value = (port, False)
        futures.append(future)

    mock_executor = MagicMock()
    mock_executor.__enter__.return_value = mock_executor
    mock_executor.__exit__.return_value = False

    mock_executor.submit.side_effect = futures

    with patch(
        "tools.port_scanner.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.port_scanner.ThreadPoolExecutor",
        return_value=mock_executor,
    ), patch(
        "tools.port_scanner.as_completed",
        return_value=futures,
    ), patch(
        "tools.port_scanner.time.perf_counter",
        side_effect=[1.0, 1.5],
    ):
        main()

    captured = capsys.readouterr()

    assert "Open ports: 0" in captured.out
    assert "Closed ports: 3" in captured.out
    assert "Scan completed." in captured.out


# ============================================================
# Validation errors
# ============================================================


def test_main_invalid_port_range(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "port_scanner",
            "--target",
            "127.0.0.1",
            "--start-port",
            "0",
            "--end-port",
            "100",
        ],
    )

    main()

    captured = capsys.readouterr()

    assert "Ports must be between 1 and 65535." in captured.out


def test_main_end_port_too_large(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "port_scanner",
            "--target",
            "127.0.0.1",
            "--start-port",
            "1",
            "--end-port",
            "65536",
        ],
    )

    main()

    captured = capsys.readouterr()

    assert "Ports must be between 1 and 65535." in captured.out


def test_main_start_port_greater_than_end(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "port_scanner",
            "--target",
            "127.0.0.1",
            "--start-port",
            "100",
            "--end-port",
            "50",
        ],
    )

    main()

    captured = capsys.readouterr()

    assert "Start port cannot be greater than end port." in captured.out


def test_main_invalid_workers(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "port_scanner",
            "--target",
            "127.0.0.1",
            "--workers",
            "0",
        ],
    )

    main()

    captured = capsys.readouterr()

    assert "Workers must be greater than 0." in captured.out


# ============================================================
# DNS resolution error
# ============================================================


def test_main_dns_resolution_error(
    monkeypatch,
    capsys,
):
    import socket

    monkeypatch.setattr(
        "sys.argv",
        [
            "port_scanner",
            "--target",
            "invalid-host",
        ],
    )

    with patch(
        "tools.port_scanner.socket.gethostbyname",
        side_effect=socket.gaierror(),
    ):
        main()

    captured = capsys.readouterr()

    assert "Could not resolve target." in captured.out


# ============================================================
# CLI argument handling
# ============================================================


def test_scan_parser_rejects_missing_target():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "scan",
            ]
        )


def test_scan_parser_accepts_all_options():
    parser = build_parser()

    args = parser.parse_args(
        [
            "scan",
            "--target",
            "192.168.1.1",
            "--start-port",
            "10",
            "--end-port",
            "100",
            "--timeout",
            "2.5",
            "--workers",
            "50",
        ]
    )

    assert args.command == "scan"
    assert args.target == "192.168.1.1"
    assert args.start_port == 10
    assert args.end_port == 100
    assert args.timeout == 2.5
    assert args.workers == 50