import ipaddress
import platform
import subprocess  # nosec B404
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_HOSTS = 4096



def ping_host(host):
    if platform.system().lower() == "windows":
        command = [
            "ping",
            "-n",
            "1",
            "-w",
            "1000",
            host,
        ]
    else:
        command = [
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            host,
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