"""Plain-HTTP page on the LAN address that hands the demo CA to a phone.

Only two paths exist: the instructions page and the *public* CA certificate. Nothing else on this
machine is reachable through it, and only private-network clients are answered. HTTP is deliberate:
a phone cannot yet trust the HTTPS certificate it is about to install the CA for. The download is a
certificate, not a secret; what protects you is that you install it on a throwaway demo phone only
and remove it afterwards (the page says how).
"""

from __future__ import annotations

import html
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from .core import NetProxy

CA_FILENAME = "cns-demo-ca.crt"

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Secure Chat demo CA</title>
<style>:root{{color-scheme:light dark}}body{{font:16px/1.5 -apple-system,system-ui,sans-serif;margin:0 auto;
padding:16px;max-width:42rem}}a.btn{{display:block;text-align:center;background:#1456b8;color:#fff;
padding:14px;border-radius:10px;text-decoration:none;font-weight:600;margin:12px 0}}code{{background:rgba(127,127,127,.2);
padding:1px 5px;border-radius:4px}}h2{{margin-top:1.6em}}</style></head><body>
<h1>Secure Chat network-attack demo</h1>
<p>This page belongs to a classroom demo on <b>{ip}</b>. Install the demo certificate only on a phone you
are happy to use for the demo, and remove it afterwards.</p>
<a class="btn" href="/{filename}">Download the demo CA certificate</a>
<p>CA: <code>{subject}</code><br>SHA-256 fingerprint: <code>{fingerprint}</code><br>
Check the fingerprint matches the one printed in the Mac's terminal.</p>
<h2>iPhone (Safari)</h2><ol>
<li>Tap the button above, then <b>Allow</b> when asked to download a configuration profile.</li>
<li>Open <b>Settings</b>; tap <b>Profile Downloaded</b> (or <b>General &rarr; VPN &amp; Device Management</b>),
choose <b>{short}</b>, tap <b>Install</b>, enter your passcode, then <b>Install</b> twice more.</li>
<li><b>Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings</b>: switch <b>on</b> full trust for
<b>{short}</b> and confirm with <b>Continue</b>.</li>
<li>Open <b>https://{ip}:{port}</b> in Safari. No warning should appear.</li>
<li>When done: <b>Settings &rarr; General &rarr; VPN &amp; Device Management</b> &rarr; the profile &rarr;
<b>Remove Profile</b>.</li></ol>
<h2>Android (Chrome)</h2><ol>
<li>Tap the button above to download <code>{filename}</code>.</li>
<li><b>Settings &rarr; Security &amp; privacy &rarr; More security &amp; privacy &rarr; Encryption &amp; credentials
&rarr; Install a certificate &rarr; CA certificate</b> (search Settings for &ldquo;CA certificate&rdquo; if the menu
differs), tap <b>Install anyway</b>, choose the downloaded file. A screen lock must be set.</li>
<li>Open <b>https://{ip}:{port}</b> in Chrome. No warning should appear.</li>
<li>When done: <b>Settings &rarr; Security &rarr; Encryption &amp; credentials &rarr; User credentials</b> &rarr;
remove the certificate.</li></ol>
<h2>Without installing</h2><p>You can instead open <b>https://{ip}:{port}</b> and accept the warning once (iPhone:
Show Details &rarr; visit this website; Android: Advanced &rarr; Proceed). The page may load, but Safari on
iPhone commonly refuses the WebSocket the chat needs, and voice calls need a trusted certificate. Installing
the CA is the reliable path.</p></body></html>"""


def _private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def ca_info(ca_pem: bytes):
    cert = x509.load_pem_x509_certificate(ca_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    from cryptography.hazmat.primitives import hashes

    fingerprint = cert.fingerprint(hashes.SHA256()).hex(":").upper()
    return der, cert.subject.rfc4514_string().replace("CN=", ""), fingerprint


def create_app(proxy: NetProxy, ca_path: Path, proxy_port: int) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    der, subject, fingerprint = ca_info(Path(ca_path).read_bytes())

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = request.client.host if request.client else ""
        if not _private(host):
            return JSONResponse({"error": "private networks only"}, status_code=403)
        proxy.note_cert_hit(host)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", response_class=HTMLResponse)
    def page():
        return PAGE.format(
            ip=html.escape(proxy.lan_ip or ""),
            port=proxy_port,
            filename=CA_FILENAME,
            subject=html.escape(subject),
            short=html.escape(subject),
            fingerprint=fingerprint,
        )

    @app.get("/" + CA_FILENAME)
    def download():
        return Response(
            der,
            media_type="application/x-x509-ca-cert",
            headers={"Content-Disposition": f'attachment; filename="{CA_FILENAME}"'},
        )

    return app
