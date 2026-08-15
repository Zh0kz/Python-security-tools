import json

from tools.reporting import save_scan_report


def test_save_scan_report(tmp_path):
    output_file = tmp_path / "scan.json"

    open_ports = [
        {
            "port": 80,
            "service": "HTTP",
            "banner": "Test Server",
        }
    ]

    save_scan_report(
        str(output_file),
        "127.0.0.1",
        1,
        100,
        open_ports,
        0.42,
    )

    assert output_file.exists()

    with open(
        output_file,
        "r",
        encoding="utf-8",
    ) as file:
        report = json.load(file)

    assert report["target"] == "127.0.0.1"
    assert report["ports"]["start"] == 1
    assert report["ports"]["end"] == 100

    assert len(report["open_ports"]) == 1

    assert report["summary"]["open"] == 1
    assert report["summary"]["closed"] == 99

    assert report["scan_time"] == 0.42

def test_save_scan_report_with_security_findings(tmp_path):
    output_file = tmp_path / "scan.json"

    open_ports = [
        {
            "port": 445,
            "service": "SMB",
            "banner": "-",
        }
    ]

    findings = [
        {
            "port": 445,
            "service": "SMB",
            "risk": "HIGH",
            "message": "SMB service detected.",
        }
    ]

    save_scan_report(
        str(output_file),
        "127.0.0.1",
        1,
        1024,
        open_ports,
        1.25,
        findings,
    )

    import json

    with open(output_file, encoding="utf-8") as file:
        report = json.load(file)

    assert report["security_findings"] == findings
    assert report["summary"]["findings"] == 1