"""Find the Mac's LAN address for the phone-as-victim mode (`--lan`).

    python -m attack_lab.netproxy.lan [--ip 192.168.1.20]   ->  prints "<ip> <interface>"

Works on a normal Wi-Fi network and on an iPhone Personal Hotspot (the Mac then gets 172.20.10.x).
Only private addresses are accepted: the attacker proxy must never be offered to the internet.
"""

import argparse
import ipaddress
import socket
import subprocess
import sys


class LanError(ValueError):
    pass


def check_private(text: str) -> str:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise LanError(f"{text!r} is not an IP address") from None
    if (
        ip.version != 4
        or not ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
    ):
        raise LanError(
            f"{ip} is not a private LAN address (10.x, 172.16-31.x or 192.168.x). "
            "The attacker proxy is never exposed on anything else."
        )
    return str(ip)


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout.strip()


def detect(override: str | None = None) -> tuple[str, str]:
    """Return (ip, interface). Raises LanError with a plain explanation."""
    if override:
        return check_private(override), "(given)"
    iface = ""
    try:  # macOS: interface of the default route, then its address
        for line in _run(["route", "-n", "get", "default"]).splitlines():
            if line.strip().startswith("interface:"):
                iface = line.split(":", 1)[1].strip()
        if iface:
            addr = _run(["ipconfig", "getifaddr", iface])
            if addr:
                return check_private(addr), iface
    except (OSError, subprocess.SubprocessError):
        pass
    try:  # portable fallback: the source address the OS would use to reach the internet
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET, nothing is sent
            return check_private(s.getsockname()[0]), iface or "(default route)"
    except (OSError, LanError):
        pass
    raise LanError(
        "Could not find a private LAN address. Connect the Mac to Wi-Fi (or to the iPhone's "
        "Personal Hotspot), or pass --lan-ip <address>."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip")
    args = parser.parse_args()
    try:
        ip, iface = detect(args.ip)
    except LanError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    print(ip, iface)


if __name__ == "__main__":
    main()
