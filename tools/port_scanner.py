import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_SERVICES = {
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


def get_service_name(port):
    return COMMON_SERVICES.get(port, "Unknown")


def scan_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            return port, True

        return port, False

    except socket.error:
        return port, False

    finally:
        sock.close()


def get_banner(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target, port))

        banner = sock.recv(1024).decode(
            errors="ignore"
        ).strip()

        return banner

    except (socket.timeout, socket.error):
        return ""

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="Fast TCP port scanner for cybersecurity learning"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "--start-port",
        type=int,
        default=1,
        help="Starting port (default: 1)"
    )

    parser.add_argument(
        "--end-port",
        type=int,
        default=1024,
        help="Ending port (default: 1024)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout in seconds (default: 0.5)"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Number of concurrent workers (default: 100)"
    )

    args = parser.parse_args()

    if args.start_port < 1 or args.end_port > 65535:
        print("[!] Ports must be between 1 and 65535.")
        return

    if args.start_port > args.end_port:
        print("[!] Start port cannot be greater than end port.")
        return

    if args.workers < 1:
        print("[!] Workers must be greater than 0.")
        return

    print("=" * 70)
    print("                    PYTHON SECURITY TOOLS")
    print("                         PORT SCANNER")
    print("=" * 70)

    print(f"\nTarget: {args.target}")
    print(f"Ports: {args.start_port}-{args.end_port}")
    print(f"Workers: {args.workers}\n")

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("[!] Could not resolve target.")
        return

    print(f"Resolved IP: {target_ip}\n")

    ports = range(args.start_port, args.end_port + 1)
    total_ports = args.end_port - args.start_port + 1

    open_ports = []

    start_time = time.perf_counter()

    print("Starting scan...\n")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:

        futures = [
            executor.submit(
                scan_port,
                target_ip,
                port,
                args.timeout
            )
            for port in ports
        ]

        completed = 0

        for future in as_completed(futures):

            port, is_open = future.result()

            completed += 1

            if is_open:
                open_ports.append(port)

                service = get_service_name(port)
                banner = get_banner(
                    target_ip,
                    port,
                    args.timeout
                )

                if not banner:
                    banner = "-"

                print(
                    f"[+] {port:<8}"
                    f"OPEN     "
                    f"{service:<15}"
                    f"{banner[:35]}"
                )

            if completed % 10 == 0 or completed == total_ports:
                print(
                    f"\rProgress: "
                    f"{completed}/{total_ports} ports scanned",
                    end=""
                )

    end_time = time.perf_counter()

    scan_time = end_time - start_time

    print("\n")

    closed_ports = total_ports - len(open_ports)

    print("=" * 70)
    print("Scan completed.")
    print(f"Open ports: {len(open_ports)}")
    print(f"Closed ports: {closed_ports}")
    print(f"Scan time: {scan_time:.2f} seconds")
    print("=" * 70)


if __name__ == "__main__":
    main()