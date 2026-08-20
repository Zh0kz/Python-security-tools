import json

from tools.reporting import save_audit_report


def test_save_audit_report(tmp_path):
    report_path = tmp_path / "audit.json"

    result = {
        "target": "127.0.0.1",
        "risk": {
            "score": 50,
            "level": "HIGH",
        },
    }

    save_audit_report(
        report_path,
        result,
    )

    assert report_path.exists()

    with report_path.open(
        "r",
        encoding="utf-8",
    ) as report_file:
        data = json.load(report_file)

    assert data["target"] == "127.0.0.1"
    assert data["risk"]["score"] == 50
    assert data["risk"]["level"] == "HIGH"