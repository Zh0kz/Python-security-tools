from tools.port_scanner import get_service_name, scan_port


def test_ssh_service():
    assert get_service_name(22) == "SSH"


def test_http_service():
    assert get_service_name(80) == "HTTP"


def test_https_service():
    assert get_service_name(443) == "HTTPS"


def test_unknown_service():
    assert get_service_name(9999) == "Unknown"


def test_closed_port():
    port, is_open = scan_port(
        "127.0.0.1",
        65534,
        0.1
    )

    assert port == 65534
    assert is_open is False