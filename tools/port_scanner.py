import argparse
import socket


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
            return True

        return False

    except socket.error:
        return False

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
        description="Simple TCP port scanner for cybersecurity learning"
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

    args = parser.parse_args()

    print("=" * 70)
    print("                    PYTHON SECURITY TOOLS")
    print("                         PORT SCANNER")
    print("=" * 70)

    print(f"\nTarget: {args.target}")
    print(f"Ports: {args.start_port}-{args.end_port}\n")

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("[!] Could not resolve target.")
        return

    print(f"Resolved IP: {target_ip}\n")

    print(
        f"{'PORT':<10}"
        f"{'STATE':<10}"
        f"{'SERVICE':<20}"
        f"BANNER"
    )

    print("-" * 70)

    for port in range(args.start_port, args.end_port + 1):

        if scan_port(target_ip, port, args.timeout):

            service = get_service_name(port)
            banner = get_banner(target_ip, port, args.timeout)

            if not banner:
                banner = "-"

            print(
                f"{port:<10}"
                f"{'OPEN':<10}"
                f"{service:<20}"
                f"{banner[:35]}"
            )

    print("\n" + "=" * 70)
    print("Scan completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()