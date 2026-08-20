import json


def save_audit_report(path, result):
    with open(
        path,
        "w",
        encoding="utf-8",
    ) as report_file:
        json.dump(
            result,
            report_file,
            indent=2,
            ensure_ascii=False,
        )

def save_scan_report(
    output_file,
    target,
    start_port,
    end_port,
    open_ports,
    scan_time,
    findings=None,
):
    if findings is None:
        findings = []

    report = {
        "target": target,
        "ports": {
            "start": start_port,
            "end": end_port,
        },
        "open_ports": open_ports,
        "security_findings": findings,
        "summary": {
            "open": len(open_ports),
            "closed": (
                end_port
                - start_port
                + 1
                - len(open_ports)
            ),
            "findings": len(findings),
        },
        "scan_time": round(scan_time, 2),
    }

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
    )