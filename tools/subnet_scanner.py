import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_HOSTS = 4096


def ping_host(host, timeout=1):
    """
    Check whether a host is reachable.

    Args:
        host: IP address or hostname.
        timeout: Timeout for the connectivity check.

    Returns:
        Tuple containing the host and whether it is reachable.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((str(host), 80))

        return host, result == 0

    except (TimeoutError, OSError):
        return host, False


def scan_subnet(network, timeout=1, workers=100):
    """
    Scan a subnet and return reachable hosts.

    Args:
        network: Network in CIDR notation.
        timeout: Connection timeout for each host.
        workers: Maximum number of concurrent workers.

    Returns:
        Sorted list of reachable host IP addresses.

    Raises:
        ValueError: If the network, workers, or network size is invalid.
    """
    try:
        subnet = ipaddress.ip_network(
            network,
            strict=False,
        )
    except ValueError as error:
        raise ValueError(
            f"Invalid network: {network}"
        ) from error

    if workers < 1:
        raise ValueError(
            "Workers must be greater than 0."
        )

    if subnet.num_addresses > MAX_HOSTS:
        raise ValueError(
            f"Network is too large. "
            f"Maximum allowed size is {MAX_HOSTS} addresses."
        )

    hosts = list(subnet.hosts())
    online_hosts = []

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = {
            executor.submit(
                ping_host,
                host,
                timeout,
            ): host
            for host in hosts
        }

        for future in as_completed(futures):
            host, is_online = future.result()

            if is_online:
                online_hosts.append(str(host))

    return sorted(
        online_hosts,
        key=ipaddress.ip_address,
    )