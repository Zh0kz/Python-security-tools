from tools.service_detection import detect_service


def test_detect_ssh():
    banner = "SSH-2.0-OpenSSH_9.6"

    assert detect_service(banner) == "SSH"


def test_detect_http():
    banner = "HTTP/1.1 200 OK\r\nServer: nginx"

    assert detect_service(banner) == "HTTP"


def test_detect_ftp():
    banner = "220 (vsftpd 3.0.5)"

    assert detect_service(banner) == "FTP"


def test_detect_smtp():
    banner = "220 mail.example.com ESMTP Postfix"

    assert detect_service(banner) == "SMTP"


def test_unknown_service():
    banner = "Some unknown service"

    assert detect_service(banner) == "Unknown"


def test_empty_banner():
    assert detect_service("") == "Unknown"


def test_none_banner():
    assert detect_service(None) == "Unknown"