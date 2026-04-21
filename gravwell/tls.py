"""TLS certificate generation and fingerprinting for the GravWell server."""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import socket
from pathlib import Path

_CERT_VALIDITY_DAYS = 3650   # 10 years


def _local_ips() -> list:
    """Return all non-loopback local IPv4 addresses."""
    seen: set = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = info[4][0]
            try:
                ip = ipaddress.IPv4Address(addr)
                if not ip.is_loopback:
                    seen.add(ip)
            except ValueError:
                pass
    except Exception:
        pass
    return list(seen)


def ensure_cert(cert_path: Path, key_path: Path) -> bool:
    """Generate a self-signed cert+key if either file is missing.

    Returns True if a new cert was generated.
    """
    if cert_path.exists() and key_path.exists():
        return False
    generate_cert(cert_path, key_path)
    return True


def generate_cert(cert_path: Path, key_path: Path) -> None:
    """Generate a self-signed RSA-2048 cert valid for 10 years.

    SANs include localhost, 127.0.0.1, the machine hostname, and all
    detected local IPv4 addresses so any local IP works without errors.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key      = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hostname = socket.gethostname()

    san_names: list = [x509.DNSName("localhost"), x509.DNSName(hostname)]
    san_ips:   list = [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
    for ip in _local_ips():
        san_ips.append(x509.IPAddress(ip))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GravWell"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=_CERT_VALIDITY_DAYS)
        )
        .add_extension(
            x509.SubjectAlternativeName(san_names + san_ips),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    try:
        key_path.chmod(0o600)
    except Exception:
        pass


def fingerprint(cert_path: Path) -> str:
    """Return the SHA-256 fingerprint as colon-separated uppercase hex pairs."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    der  = cert.public_bytes(Encoding.DER)
    h    = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))
