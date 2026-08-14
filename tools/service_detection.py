SERVICE_SIGNATURES = {
    "SSH": [
        "SSH-",
        "OpenSSH",
    ],
    "FTP": [
        "vsftpd",
        "ProFTPD",
        "Pure-FTPd",
        "FileZilla",
    ],
    "SMTP": [
        "SMTP",
        "Postfix",
        "Exim",
        "ESMTP",
    ],
    "HTTP": [
        "HTTP/",
        "Server:",
        "nginx",
        "Apache",
        "Microsoft-IIS",
    ],
    "MySQL": [
        "mysql",
        "MySQL",
    ],
    "PostgreSQL": [
        "PostgreSQL",
        "postgres",
    ],
}


def detect_service(banner):
    """
    Detect a service using a server banner.

    Returns:
        str: Detected service name or "Unknown".
    """

    if not banner:
        return "Unknown"

    banner_lower = banner.lower()

    for service, signatures in SERVICE_SIGNATURES.items():
        for signature in signatures:
            if signature.lower() in banner_lower:
                return service

    return "Unknown"