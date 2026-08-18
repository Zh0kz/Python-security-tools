from unittest.mock import MagicMock, patch

import pytest

from tools.port_scanner import (
    get_banner,
    get_service_name,
    run_scan,
    scan_port,
)

# ============================================================
# Service detection
# ============================================================


def test_ssh_service():
    assert get_service_name(22) == "SSH"


def test_http_service():
    assert get_service_name(80) == "HTTP"


def test_https_service():
    assert get_service_name(443) == "HTTPS"


def test_unknown_service():
    assert get_service_name(9999) == "Unknown"


def test_all_common_services():
    expected_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Proxy",
    }

    for port, service in expected_services.items():
        assert get_service_name(port) == service


# ============================================================
# scan_port()
# ============================================================


def test_scan_port_open():
    mock_socket = MagicMock()

    mock_socket.connect_ex.return_value = 0

    with patch(
        "tools.port_scanner.socket.socket",
        return_value=mock_socket,
    ):
        port, is_open = scan_port(
            "127.0.0.1",
            80,
            0.5,
        )

    assert port == 80
    assert is_open is True

    mock_socket.settimeout.assert_called_once_with(0.5)
    mock_socket.connect_ex.assert_called_once_with(
        ("127.0.0.1", 80)
    )
    mock_socket.close.assert_called_once()


def test_scan_port_closed():
    mock_socket = MagicMock()

    mock_socket.connect_ex.return_value = 1

    with patch(
        "tools.port_scanner.socket.socket",
        return_value=mock_socket,
    ):
        port, is_open = scan_port(
            "127.0.0.1",
            80,
            0.5,
        )

    assert port == 80
    assert is_open is False

    mock_socket.close.assert_called_once()


def test_scan_port_socket_error():
    mock_socket = MagicMock()

    mock_socket.connect_ex.side_effect = OSError(
        "Connection failed"
    )

    with patch(
        "tools.port_scanner.socket.socket",
        return_value=mock_socket,
    ):
        port, is_open = scan_port(
            "127.0.0.1",
            80,
            0.5,
        )

    assert port == 80
    assert is_open is False

    mock_socket.close.assert_called_once()


# ============================================================
# get_banner()
# ============================================================


def test_get_banner_success():
    mock_socket = MagicMock()

    mock_socket.recv.return_value = (
        b"SSH-2.0-OpenSSH_9.6\n"
    )

    with patch(
        "tools.port_scanner.socket.socket",
        return_value=mock_socket,
    ):
        banner = get_banner(
            "127.0.0.1",
            22,
            0.5,
        )

    assert banner == "SSH-2.0-OpenSSH_9.6"

    mock_socket.settimeout.assert_called_once_with(0.5)
    mock_socket.connect.assert_called_once_with(
        ("127.0.0.1", 22)
    )
    mock_socket.recv.assert_called_once_with(1024)
    mock_socket.close.assert_called_once()


def test_get_banner_empty():
    mock_socket = MagicMock()

    mock_socket.recv.return_value = b""

    with patch(
        "tools.port_scanner.socket.socket",
        return_value=mock_socket,
    ):
        banner = get_banner(
            "127.0.0.1",
            80,
            0.5,
        )

    assert banner == ""

    mock_socket.close.assert_called_once()


def test_get_banner_socket_timeout():

    mock_socket = MagicMock()

    mock_socket.recv.side_effect = TimeoutError()

    with patch(
        "tools.port_scanner.socket.socket",
        return_value=mock_socket,
    ):
        banner = get_banner(
            "127.0.0.1",
            80,
            0.5,
        )

    assert banner == ""

    mock_socket.close.assert_called_once()


def test_get_banner_socket_error():
    mock_socket = MagicMock()

    mock_socket.connect.side_effect = OSError(
        "Connection failed"
    )

    with patch(
        "tools.port_scanner.socket.socket",
        return_value=mock_socket,
    ):
        banner = get_banner(
            "127.0.0.1",
            80,
            0.5,
        )

    assert banner == ""

    mock_socket.close.assert_called_once()


# ============================================================
# run_scan()
# ============================================================


def test_run_scan_open_and_closed_ports():
    def fake_scan_port(
        target,
        port,
        timeout,
    ):
        return port, port in (22, 80)

    with patch(
        "tools.port_scanner.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.port_scanner.scan_port",
        side_effect=fake_scan_port,
    ):
        result = run_scan(
            "localhost",
            20,
            100,
            timeout=0.1,
            workers=5,
        )

    assert result == [22, 80]


def test_run_scan_returns_sorted_ports():
    def fake_scan_port(
        target,
        port,
        timeout,
    ):
        return port, port in (22, 80, 90)

    with patch(
        "tools.port_scanner.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.port_scanner.scan_port",
        side_effect=fake_scan_port,
    ):
        result = run_scan(
            "localhost",
            1,
            100,
            timeout=0.1,
            workers=5,
        )

    assert result == [22, 80, 90]


def test_run_scan_no_open_ports():
    def fake_scan_port(
        target,
        port,
        timeout,
    ):
        return port, False

    with patch(
        "tools.port_scanner.socket.gethostbyname",
        return_value="127.0.0.1",
    ), patch(
        "tools.port_scanner.scan_port",
        side_effect=fake_scan_port,
    ):
        result = run_scan(
            "localhost",
            1,
            10,
            timeout=0.1,
            workers=2,
        )

    assert result == []


# ============================================================
# run_scan() validation
# ============================================================


def test_run_scan_invalid_start_port():
    with pytest.raises(
        ValueError,
        match="Ports must be between 1 and 65535",
    ):
        run_scan(
            "localhost",
            0,
            100,
        )


def test_run_scan_invalid_end_port():
    with pytest.raises(
        ValueError,
        match="Ports must be between 1 and 65535",
    ):
        run_scan(
            "localhost",
            1,
            65536,
        )


def test_run_scan_start_greater_than_end():
    with pytest.raises(
        ValueError,
        match="Start port cannot be greater than end port",
    ):
        run_scan(
            "localhost",
            100,
            1,
        )


def test_run_scan_invalid_workers():
    with pytest.raises(
        ValueError,
        match="Workers must be greater than 0",
    ):
        run_scan(
            "localhost",
            1,
            100,
            workers=0,
        )


def test_run_scan_dns_error():
    import socket

    with patch(
        "tools.port_scanner.socket.gethostbyname",
        side_effect=socket.gaierror(),
    ), pytest.raises(
        ValueError,
        match="Could not resolve target",
    ):
        run_scan(
            "invalid-target",
            1,
            100,
        )