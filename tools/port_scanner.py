import argparse
import socket


def scan_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    result = sock.connect_ex((target, port))
    sock.close()

    return result == 0


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

    print("=" * 50)
    print("           PYTHON SECURITY TOOLS")
    print("                PORT SCANNER")
    print("=" * 50)

    print(f"\nTarget: {args.target}")
    print(f"Ports: {args.start_port}-{args.end_port}\n")

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("[!] Could not resolve target.")
        return

    for port in range(args.start_port, args.end_port + 1):
        if scan_port(target_ip, port, args.timeout):
            print(f"[+] Port {port} OPEN")

    print("\n" + "=" * 50)
    print("Scan completed.")
    print("=" * 50)


if __name__ == "__main__":
    main()