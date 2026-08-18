import pytest

from tools.subnet_scanner import scan_subnet


def test_scan_subnet_too_large():
    with pytest.raises(ValueError, match="too large"):
        scan_subnet(
            "10.0.0.0/8"
        )

def test_scan_subnet_localhost(monkeypatch):
    def fake_ping(host, timeout=1):
        return host, str(host) == "127.0.0.1"

    monkeypatch.setattr(
        "tools.subnet_scanner.ping_host",
        fake_ping,
    )

    result = scan_subnet(
        "127.0.0.0/30",
        workers=2,
    )

    assert "127.0.0.1" in result


def test_scan_subnet_invalid_network():
    with pytest.raises(ValueError):
        scan_subnet(
            "invalid-network"
        )


def test_scan_subnet_invalid_workers():
    with pytest.raises(ValueError):
        scan_subnet(
            "127.0.0.0/30",
            workers=0,
        )