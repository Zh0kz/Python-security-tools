import json


def save_scan_report(
    output_file,
    target,
    start_port,
    end_port,
    open_ports,
    scan_time,
):
    report = {
        "target": target,
        "ports": {
            "start": start_port,
            "end": end_port,
        },
        "open_ports": open_ports,
        "summary": {
            "open": len(open_ports),
            "closed": (
                end_port
                - start_port
                + 1
                - len(open_ports)
            ),
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