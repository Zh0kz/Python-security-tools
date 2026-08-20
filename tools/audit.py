import socket
import time

from tools.port_scanner import (
    get_banner,
    get_service_name,
    run_scan,
)
from tools.risk import calculate_risk
from tools.service_detection import detect_service
from tools.vulnerability_checks import check_services


def run_audit(
    target,
    start_port=1,
    end_port=1024,
    timeout=0.5,
    workers=100,
):
    """
    Run a complete security audit against a target.

    The audit performs:
    - target resolution
    - TCP port scanning
    - service identification
    - banner detection
    - safe security checks

    Returns:
        dict: Structured security audit result.
    """

    start_time = time.perf_counter()

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as error:
        raise ValueError(
            f"Could not resolve target: {target}"
        ) from error

    open_ports = run_scan(
        target_ip,
        start_port,
        end_port,
        timeout,
        workers,
    )

    services = []

    for port in open_ports:
        service = get_service_name(port)

        banner = get_banner(
            target_ip,
            port,
            timeout,
        )

        detected_service = detect_service(banner)

        if detected_service != "Unknown":
            service = detected_service

        services.append(
            {
                "port": port,
                "service": service,
                "banner": banner,
            }
        )

    findings = check_services(services)

    risk = calculate_risk(findings)

    audit_time = time.perf_counter() - start_time

    total_ports = end_port - start_port + 1

    return {
        "target": target,
        "resolved_ip": target_ip,
        "ports": {
            "start": start_port,
            "end": end_port,
            "total": total_ports,
            "open": len(open_ports),
            "closed": total_ports - len(open_ports),
        },
        "services": services,
        "findings": findings,
        "risk": risk,
        "scan_time": round(audit_time, 2),
    }