from unittest.mock import patch

from tools.audit import run_audit


@patch("tools.audit.check_services")
@patch("tools.audit.detect_service")
@patch("tools.audit.get_banner")
@patch("tools.audit.get_service_name")
@patch("tools.audit.run_scan")
@patch("tools.audit.socket.gethostbyname")
def test_run_audit(
    mock_gethostbyname,
    mock_run_scan,
    mock_get_service_name,
    mock_get_banner,
    mock_detect_service,
    mock_check_services,
):
    mock_gethostbyname.return_value = "127.0.0.1"

    mock_run_scan.return_value = [
        22,
        80,
    ]

    mock_get_service_name.side_effect = [
        "SSH",
        "HTTP",
    ]

    mock_get_banner.side_effect = [
        "SSH-2.0-OpenSSH",
        "HTTP/1.1 200 OK",
    ]

    mock_detect_service.side_effect = [
        "SSH",
        "HTTP",
    ]

    mock_check_services.return_value = [
        {
            "port": 22,
            "service": "SSH",
            "risk": "INFO",
            "message": "SSH service detected on port 22.",
        },
        {
            "port": 80,
            "service": "HTTP",
            "risk": "LOW",
            "message": "HTTP service detected on port 80.",
        },
    ]

    result = run_audit(
        "example.com",
        start_port=1,
        end_port=100,
        timeout=0.5,
        workers=10,
    )

    assert result["risk"]["score"] == 10
    assert result["risk"]["level"] == "LOW"

    assert result["risk"]["breakdown"] == {
        "INFO": 1,
        "LOW": 1,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    assert result["target"] == "example.com"
    assert result["resolved_ip"] == "127.0.0.1"

    assert result["ports"]["start"] == 1
    assert result["ports"]["end"] == 100
    assert result["ports"]["total"] == 100
    assert result["ports"]["open"] == 2
    assert result["ports"]["closed"] == 98

    assert len(result["services"]) == 2

    assert result["services"][0]["port"] == 22
    assert result["services"][0]["service"] == "SSH"
    assert result["services"][0]["banner"] == "SSH-2.0-OpenSSH"

    assert result["services"][1]["port"] == 80
    assert result["services"][1]["service"] == "HTTP"

    assert len(result["findings"]) == 2

    mock_run_scan.assert_called_once_with(
        "127.0.0.1",
        1,
        100,
        0.5,
        10,
    )


@patch("tools.audit.socket.gethostbyname")
def test_run_audit_invalid_target(mock_gethostbyname):
    import socket

    mock_gethostbyname.side_effect = socket.gaierror()

    try:
        run_audit("invalid-target")
        assert False
    except ValueError as error:
        assert "Could not resolve target" in str(error)


