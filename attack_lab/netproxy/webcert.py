"""Local HTTPS certificate for the browser flavour of the network attacker demo.

    python -m attack_lab.netproxy.webcert [--dir data/network_attack] [--ip 192.168.1.20 ...]

Writes into the (git-ignored) directory:

* ``web.crt`` / ``web.key``  the server certificate (SAN: localhost, 127.0.0.1, ::1 and every ``--ip``)
* ``ca.crt``                 the public demo CA that signed it: this is what a phone installs
* ``ca.key``                 the CA private key, mode 0600, never served or printed

and prints one line: ``<mode> <spki-sha256-base64>``. ``mode`` is ``mkcert`` when mkcert and its
local CA exist (browsers that trust the mkcert CA then trust the certificate), otherwise
``selfsigned`` (our own tiny CA). The CA is kept when only the IP set changes (new Wi-Fi), so a phone
that installed it once keeps working. The SPKI hash lets the launcher start demo Chrome windows
that accept exactly this one public key (``--ignore-certificate-errors-spki-list``) in throwaway
profiles, so nothing is added to the Mac's trust store.
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
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_NAME = "Secure Chat Network-Attack Demo CA"


def spki_hash(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def _wanted_ips(ips) -> set:
    return {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")} | {
        ipaddress.ip_address(i) for i in ips
    }


def covers(cert_path: Path, key_path: Path, ips=()) -> bool:
    """True if the certificate is valid for >7 days and names localhost plus every wanted IP."""
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        left = cert.not_valid_after_utc - datetime.now(timezone.utc)
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        have = set(names.get_values_for_type(x509.IPAddress))
        return (
            left > timedelta(days=7)
            and "localhost" in names.get_values_for_type(x509.DNSName)
            and _wanted_ips(ips) <= have
            and key_path.exists()
        )
    except (OSError, ValueError, x509.ExtensionNotFound):
        return False


usable = covers  # backwards-compatible name


def mkcert_ready() -> bool:
    exe = shutil.which("mkcert")
    if not exe:
        return False
    out = subprocess.run([exe, "-CAROOT"], capture_output=True, text=True).stdout.strip()
    return bool(out) and (Path(out) / "rootCA.pem").exists()


def _write_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _load_or_make_ca(directory: Path):
    ca_crt, ca_key = directory / "ca.crt", directory / "ca.key"
    try:
        cert = x509.load_pem_x509_certificate(ca_crt.read_bytes())
        key = serialization.load_pem_private_key(ca_key.read_bytes(), None)
        if cert.not_valid_after_utc - datetime.now(timezone.utc) > timedelta(days=30):
            return cert, key
    except (OSError, ValueError):
        pass
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    ca_crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(ca_key, key)
    return cert, key


def generate(directory: Path, ips=()) -> tuple[str, Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    ips = sorted({str(ipaddress.ip_address(i)) for i in ips})
    cert_path, key_path = directory / "web.crt", directory / "web.key"
    mode = "mkcert" if mkcert_ready() else "selfsigned"
    marker = directory / "mode"
    if covers(cert_path, key_path, ips) and marker.exists() and marker.read_text() == mode:
        return mode, cert_path, key_path
    if mode == "mkcert":
        subprocess.run(
            ["mkcert", "-cert-file", str(cert_path), "-key-file", str(key_path)]
            + ["localhost", "127.0.0.1", "::1", *ips],
            check=True,
            capture_output=True,
        )
        root = subprocess.run(["mkcert", "-CAROOT"], capture_output=True, text=True).stdout.strip()
        (directory / "ca.crt").write_bytes((Path(root) / "rootCA.pem").read_bytes())  # public only
    else:
        ca_cert, ca_key = _load_or_make_ca(directory)
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        sans += [x509.IPAddress(ipaddress.ip_address(i)) for i in ["::1", *ips]]
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))  # phones reject leaves valid > 398 days
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        _write_key(key_path, key)
    marker.write_text(mode)
    return mode, cert_path, key_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default="data/network_attack")
    parser.add_argument("--ip", action="append", default=[], help="extra IP for the SAN (LAN IP)")
    args = parser.parse_args()
    mode, cert_path, _ = generate(Path(args.dir), args.ip)
    print(mode, spki_hash(cert_path.read_bytes()))


if __name__ == "__main__":
    main()
