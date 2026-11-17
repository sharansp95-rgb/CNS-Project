"""Local HTTPS certificate for the browser flavour of the network attacker demo.

    python -m attack_lab.netproxy.webcert [--dir data/network_attack]

Writes ``web.crt``/``web.key`` (git-ignored ``data/``) and prints one line:
``<mode> <spki-sha256-base64>``. ``mode`` is ``mkcert`` when mkcert is installed and its local CA
exists (browsers then trust the certificate with no further step), otherwise ``selfsigned``.
The SPKI hash lets the launcher start demo Chrome windows that accept exactly this one public key
(``--ignore-certificate-errors-spki-list``) in their own throwaway profiles, so nothing is added
to the system trust store and no other site becomes trusted.
"""

import argparse
import base64
import hashlib
import ipaddress
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def spki_hash(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def usable(cert_path: Path, key_path: Path) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        left = cert.not_valid_after_utc - datetime.now(timezone.utc)
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return (
            left > timedelta(days=7)
            and "localhost" in names.get_values_for_type(x509.DNSName)
            and key_path.exists()
        )
    except (OSError, ValueError, x509.ExtensionNotFound):
        return False


def mkcert_ready() -> bool:
    exe = shutil.which("mkcert")
    if not exe:
        return False
    out = subprocess.run([exe, "-CAROOT"], capture_output=True, text=True).stdout.strip()
    return bool(out) and (Path(out) / "rootCA.pem").exists()


def generate(directory: Path) -> tuple[str, Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / "web.crt", directory / "web.key"
    mode = "mkcert" if mkcert_ready() else "selfsigned"
    marker = directory / "mode"
    if usable(cert_path, key_path) and marker.exists() and marker.read_text() == mode:
        return mode, cert_path, key_path
    if mode == "mkcert":
        subprocess.run(
            [
                "mkcert",
                "-cert-file",
                str(cert_path),
                "-key-file",
                str(key_path),
                "localhost",
                "127.0.0.1",
                "::1",
            ],
            check=True,
            capture_output=True,
        )
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
    marker.write_text(mode)
    return mode, cert_path, key_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default="data/network_attack")
    args = parser.parse_args()
    mode, cert_path, _ = generate(Path(args.dir))
    print(mode, spki_hash(cert_path.read_bytes()))


if __name__ == "__main__":
    main()
