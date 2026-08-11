import socket


def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    result = sock.connect_ex((target, port))
    sock.close()

    return result == 0


def main():
    target = input("Target IP: ")

    print(f"\nScanning {target}...\n")

    for port in range(1, 1025):
        if scan_port(target, port):
            print(f"[+] Port {port} OPEN")


if __name__ == "__main__":
    main()