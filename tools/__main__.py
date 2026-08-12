import argparse

from tools.hash_checker import calculate_hash

from tools.file_integrity_monitor import (
    create_baseline,
    save_baseline,
    load_baseline,
    check_integrity,
)

from tools.port_scanner import (
    scan_port,
    get_service_name,
    get_banner,
)

def scan_command(args):
    import socket
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("[!] Could not resolve target.")
        return 1

    if args.start_port < 1 or args.end_port > 65535:
        print("[!] Ports must be between 1 and 65535.")
        return 1

    if args.start_port > args.end_port:
        print("[!] Start port cannot be greater than end port.")
        return 1

    if args.workers < 1:
        print("[!] Workers must be greater than 0.")
        return 1

    print("=" * 70)
    print("                    PYTHON SECURITY TOOLS")
    print("                         PORT SCANNER")
    print("=" * 70)

    print(f"\nTarget: {args.target}")
    print(f"Resolved IP: {target_ip}")
    print(f"Ports: {args.start_port}-{args.end_port}")
    print(f"Workers: {args.workers}\n")

    ports = range(
        args.start_port,
        args.end_port + 1
    )

    total_ports = (
        args.end_port - args.start_port + 1
    )

    open_ports = []

    start_time = time.perf_counter()

    print("Starting scan...\n")

    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:

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

    scan_time = time.perf_counter() - start_time

    print("\n")

    closed_ports = (
        total_ports - len(open_ports)
    )

    print("=" * 70)
    print("Scan completed.")
    print(f"Open ports: {len(open_ports)}")
    print(f"Closed ports: {closed_ports}")
    print(f"Scan time: {scan_time:.2f} seconds")
    print("=" * 70)

    return 0

def hash_command(args):
    file_hash = calculate_hash(
        args.file,
        args.algorithm
    )

    print(f"File: {args.file}")
    print(f"Algorithm: {args.algorithm.upper()}")
    print(f"Hash: {file_hash}")


def fim_baseline_command(args):
    baseline = create_baseline(args.directory)

    save_baseline(
        baseline,
        args.output
    )

    print(f"Baseline created: {args.output}")
    print(f"Files monitored: {len(baseline)}")


def fim_check_command(args):
    baseline = load_baseline(args.baseline)

    result = check_integrity(
        args.directory,
        baseline
    )

    print("File Integrity Check")
    print("=" * 40)
    print(f"Added:    {len(result['added'])}")
    print(f"Deleted:  {len(result['deleted'])}")
    print(f"Modified: {len(result['modified'])}")

    if result["added"]:
        print("\nAdded files:")

        for path in result["added"]:
            print(f"  + {path}")

    if result["deleted"]:
        print("\nDeleted files:")

        for path in result["deleted"]:
            print(f"  - {path}")

    if result["modified"]:
        print("\nModified files:")

        for path in result["modified"]:
            print(f"  ! {path}")

    if any(result.values()):
        print("\nSTATUS: INTEGRITY CHECK FAILED")
        return 1

    print("\nSTATUS: INTEGRITY OK")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m tools",
        description="Python Security Tools"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )
    # ==========================
    # PORT SCANNER
    # ==========================

    scan_parser = subparsers.add_parser(
        "scan",
        help="TCP port scanner"
    )

    scan_parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or hostname"
    )

    scan_parser.add_argument(
        "--start-port",
        type=int,
        default=1,
        help="Starting port"
    )

    scan_parser.add_argument(
        "--end-port",
        type=int,
        default=1024,
        help="Ending port"
    )

    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout"
    )

    scan_parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Number of concurrent workers"
    )

    scan_parser.set_defaults(
        func=scan_command
    )
    
    # ==========================
    # HASH
    # ==========================

    hash_parser = subparsers.add_parser(
        "hash",
        help="Calculate a file hash"
    )

    hash_parser.add_argument(
        "--file",
        required=True,
        help="Path to the file"
    )

    hash_parser.add_argument(
        "--algorithm",
        choices=["md5", "sha256", "sha512"],
        default="sha256",
        help="Hash algorithm"
    )

    hash_parser.set_defaults(
        func=hash_command
    )

    # ==========================
    # FIM
    # ==========================

    fim_parser = subparsers.add_parser(
        "fim",
        help="File Integrity Monitor"
    )

    fim_subparsers = fim_parser.add_subparsers(
        dest="fim_command",
        required=True
    )

    # FIM baseline

    baseline_parser = fim_subparsers.add_parser(
        "baseline",
        help="Create a file integrity baseline"
    )

    baseline_parser.add_argument(
        "--directory",
        required=True,
        help="Directory to monitor"
    )

    baseline_parser.add_argument(
        "--output",
        default="baseline.json",
        help="Baseline output file"
    )

    baseline_parser.set_defaults(
        func=fim_baseline_command
    )

    # FIM check

    check_parser = fim_subparsers.add_parser(
        "check",
        help="Check file integrity"
    )

    check_parser.add_argument(
        "--directory",
        required=True,
        help="Directory to check"
    )

    check_parser.add_argument(
        "--baseline",
        default="baseline.json",
        help="Baseline file"
    )

    check_parser.set_defaults(
        func=fim_check_command
    )

    return parser


def main():
    parser = build_parser()

    args = parser.parse_args()

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())