import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_HOSTS = 4096


def ping_host(host, timeout=1):
    """
    Check whether a host is reachable.

    Args:
        host: IP address or hostname.
        timeout: Timeout for the connectivity check in seconds.

    Returns:
        Tuple containing host and online status.
    """
    if platform.system().lower() == "windows":
        timeout_ms = max(1, int(timeout * 1000))

        command = [
            "ping",
            "-n",
            "1",
            "-w",
            str(timeout_ms),
            str(host),
        ]
    else:
        timeout_seconds = max(1, int(timeout))

        command = [
            "ping",
            "-c",
            "1",
            "-W",
            str(timeout_seconds),
            str(host),
        ]

    try:
        result = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
        )

        return host, result.returncode == 0

    except OSError:
        return host, False


def scan_subnet(network, timeout=1, workers=100):
    """
    Scan a subnet and return reachable hosts.

    Args:
        network: Network in CIDR notation.
        timeout: Ping timeout in seconds.
        workers: Maximum number of concurrent workers.

    Returns:
        Sorted list of reachable IP addresses.

    Raises:
        ValueError: If the network or worker count is invalid.
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