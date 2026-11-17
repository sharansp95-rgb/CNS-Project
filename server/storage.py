"""Object storage for end-to-end encrypted attachments.

The relay never reads attachment plaintext: every object stored here is
ciphertext produced in the sender's browser. Two backends share one interface:

* ``LocalStorage`` – a directory (development, tests, the Attack Lab). Its
  "presigned" URLs are HMAC-signed, short-lived URLs served by this app.
* ``S3Storage`` – any path-style SigV4 S3 API (Neon Object Storage in
  production). Presigned URLs point straight at the bucket, so file bytes never
  pass through this server. Implemented with the standard library plus httpx so
  no AWS SDK is required.

Secrets are read from the environment by :func:`storage_from_env`; they are never
logged and never part of a presigned URL (only the access key id and signature).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

KEY_RE = re.compile(r"^att/[0-9a-f]{32}$")


class StorageError(Exception):
    pass


def _check_key(key):
    if not isinstance(key, str) or not KEY_RE.match(key):
        raise StorageError("invalid object key")


class LocalStorage:
    """Directory-backed store whose signed URLs are served by the app itself."""

    kind = "local"
    direct = False  # bytes pass through this process (dev/test/lab only)

    def __init__(self, root=None, secret=None):
        self.root = Path(root or tempfile.mkdtemp(prefix="cns-attachments-"))
        self.root.mkdir(parents=True, exist_ok=True)
        self.secret = secret or os.urandom(32)
        self._lock = threading.Lock()

    def path(self, key):
        _check_key(key)
        return self.root / key.split("/", 1)[1]

    def _sig(self, op, key, expires, size=None):
        msg = f"{op}\n{key}\n{expires}\n{size if size is not None else ''}".encode()
        return hmac.new(self.secret, msg, hashlib.sha256).hexdigest()

    def presign_put(self, key, size, expires_in=300):
        _check_key(key)
        exp = int(time.time()) + expires_in
        sig = self._sig("put", key, exp, size)
        return {
            "method": "PUT",
            "url": f"/api/attachments/object/{key.split('/', 1)[1]}?op=put&exp={exp}&size={size}&sig={sig}",
            "headers": {},
        }

    def presign_get(self, key, expires_in=300):
        _check_key(key)
        exp = int(time.time()) + expires_in
        sig = self._sig("get", key, exp)
        return f"/api/attachments/object/{key.split('/', 1)[1]}?op=get&exp={exp}&sig={sig}"

    def verify(self, op, key, exp, sig, size=None):
        try:
            exp = int(exp)
        except (TypeError, ValueError):
            return False
        if exp < time.time():
            return False
        return hmac.compare_digest(self._sig(op, key, exp, size), sig or "")

    def head(self, key):
        try:
            return self.path(key).stat().st_size
        except FileNotFoundError:
            return None

    def read(self, key):
        return self.path(key).read_bytes()

    def write(self, key, data):
        target = self.path(key)
        tmp = target.with_suffix(".part")
        tmp.write_bytes(data)
        tmp.replace(target)

    def delete(self, key):
        try:
            self.path(key).unlink()
        except FileNotFoundError:
            pass

    def keys(self):
        return [f"att/{p.name}" for p in self.root.iterdir() if KEY_RE.match(f"att/{p.name}")]

    def purge(self):
        for key in self.keys():
            self.delete(key)


def _uri_encode(value, keep_slash=False):
    return quote(value, safe="/" if keep_slash else "")


class S3Storage:
    """Path-style SigV4 client for an S3-compatible endpoint (Neon Object Storage)."""

    kind = "s3"
    direct = True

    def __init__(self, endpoint, bucket, region, access_key_id, secret_access_key, timeout=15):
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/"):
            raise ValueError("S3_ENDPOINT must be an https origin")
        self.endpoint = f"https://{parts.netloc}"
        self.host = parts.netloc
        self.bucket, self.region = bucket, region
        self.access_key_id = access_key_id
        self._secret = secret_access_key
        self.timeout = timeout

    @property
    def origin(self):
        return self.endpoint

    def _signing_key(self, date):
        key = ("AWS4" + self._secret).encode()
        for part in (date, self.region, "s3", "aws4_request"):
            key = hmac.new(key, part.encode(), hashlib.sha256).digest()
        return key

    def _canonical_uri(self, key=None):
        path = "/" + self.bucket + ("/" + key if key else "")
        return _uri_encode(path, keep_slash=True)

    def _sign(self, method, key, query, headers, payload_hash, now):
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        date = stamp[:8]
        signed_names = ";".join(sorted(h.lower() for h in headers))
        canon_headers = "".join(
            f"{h.lower()}:{str(headers[h]).strip()}\n" for h in sorted(headers, key=str.lower)
        )
        canon_query = "&".join(
            f"{_uri_encode(k)}={_uri_encode(v)}" for k, v in sorted(query.items())
        )
        canonical = "\n".join(
            [method, self._canonical_uri(key), canon_query, canon_headers, signed_names, payload_hash]
        )
        scope = f"{date}/{self.region}/s3/aws4_request"
        to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()]
        )
        signature = hmac.new(
            self._signing_key(date), to_sign.encode(), hashlib.sha256
        ).hexdigest()
        return signature, signed_names, scope, canon_query, stamp

    def _presign(self, method, key, expires_in, extra_headers=None):
        _check_key(key)
        now = datetime.now(timezone.utc)
        headers = {"host": self.host, **(extra_headers or {})}
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        scope = f"{stamp[:8]}/{self.region}/s3/aws4_request"
        query = {
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": f"{self.access_key_id}/{scope}",
            "X-Amz-Date": stamp,
            "X-Amz-Expires": str(int(expires_in)),
            "X-Amz-SignedHeaders": ";".join(sorted(h.lower() for h in headers)),
        }
        signature, _, _, canon_query, _ = self._sign(
            method, key, query, headers, "UNSIGNED-PAYLOAD", now
        )
        return f"{self.endpoint}{self._canonical_uri(key)}?{canon_query}&X-Amz-Signature={signature}"

    def presign_put(self, key, size, expires_in=300):
        # Content-Length is a signed header, so the bucket itself rejects any
        # upload whose size differs from what the client declared at init.
        return {
            "method": "PUT",
            "url": self._presign("PUT", key, expires_in, {"content-length": str(int(size))}),
            "headers": {},
        }

    def presign_get(self, key, expires_in=300):
        return self._presign("GET", key, expires_in)

    def _request(self, method, key=None, query=None, body=b"", extra=None):
        import httpx

        now = datetime.now(timezone.utc)
        payload_hash = hashlib.sha256(body).hexdigest()
        headers = {
            "host": self.host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": now.strftime("%Y%m%dT%H%M%SZ"),
            **(extra or {}),
        }
        query = query or {}
        signature, signed, scope, canon_query, _ = self._sign(
            method, key, query, headers, payload_hash, now
        )
        auth = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key_id}/{scope}, "
            f"SignedHeaders={signed}, Signature={signature}"
        )
        send = {k: v for k, v in headers.items() if k != "host"}
        send["Authorization"] = auth
        url = f"{self.endpoint}{self._canonical_uri(key)}" + (f"?{canon_query}" if canon_query else "")
        try:
            return httpx.request(method, url, headers=send, content=body, timeout=self.timeout)
        except httpx.HTTPError as exc:  # network failure: never echo the URL
            raise StorageError(f"storage request failed: {type(exc).__name__}") from None

    def head(self, key):
        _check_key(key)
        r = self._request("HEAD", key)
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise StorageError(f"storage HEAD failed: {r.status_code}")
        return int(r.headers["content-length"])

    def read(self, key):
        _check_key(key)
        r = self._request("GET", key)
        if r.status_code != 200:
            raise StorageError(f"storage GET failed: {r.status_code}")
        return r.content

    def write(self, key, data):
        _check_key(key)
        r = self._request("PUT", key, body=data)
        if r.status_code not in (200, 201):
            raise StorageError(f"storage PUT failed: {r.status_code}")

    def delete(self, key):
        _check_key(key)
        r = self._request("DELETE", key)
        if r.status_code not in (200, 204, 404):
            raise StorageError(f"storage DELETE failed: {r.status_code}")

    def keys(self):
        import xml.etree.ElementTree as ET

        out, token = [], None
        while True:
            q = {"list-type": "2", "prefix": "att/"}
            if token:
                q["continuation-token"] = token
            r = self._request("GET", None, query=q)
            if r.status_code != 200:
                raise StorageError(f"storage LIST failed: {r.status_code}")
            root = ET.fromstring(r.content)
            ns = {"s": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
            find = (lambda n: root.findall(f"s:{n}", ns)) if ns else root.findall
            out += [e.findtext("s:Key" if ns else "Key", namespaces=ns or None) for e in find("Contents")]
            trunc = root.findtext("s:IsTruncated" if ns else "IsTruncated", namespaces=ns or None)
            if trunc != "true":
                return out
            token = root.findtext(
                "s:NextContinuationToken" if ns else "NextContinuationToken", namespaces=ns or None
            )

    def put_cors(self, origins):
        """Restrict browser access to the given exact origins (PutBucketCors)."""
        rules = (
            "<CORSConfiguration><CORSRule>"
            + "".join(f"<AllowedOrigin>{o}</AllowedOrigin>" for o in origins)
            + "<AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod>"
            + "<AllowedMethod>HEAD</AllowedMethod>"
            + "<AllowedHeader>*</AllowedHeader><ExposeHeader>ETag</ExposeHeader>"
            + "<MaxAgeSeconds>600</MaxAgeSeconds></CORSRule></CORSConfiguration>"
        ).encode()
        import base64

        r = self._request(
            "PUT",
            None,
            query={"cors": ""},
            body=rules,
            extra={"content-md5": base64.b64encode(hashlib.md5(rules).digest()).decode()},
        )
        if r.status_code not in (200, 204):
            raise StorageError(f"PutBucketCors failed: {r.status_code}")

    def purge(self):
        for key in self.keys():
            self.delete(key)


def storage_from_env(env=None, *, production=False):
    """Select the backend. Production requires the S3 backend and all its settings."""
    env = os.environ if env is None else env
    backend = env.get("STORAGE_BACKEND") or ("s3" if production else "local")
    if backend == "local":
        if production:
            raise ValueError("Production attachments require STORAGE_BACKEND=s3")
        return LocalStorage(env.get("LOCAL_STORAGE_DIR") or None)
    if backend != "s3":
        raise ValueError("STORAGE_BACKEND must be local or s3")
    needed = ("S3_ENDPOINT", "S3_BUCKET", "S3_REGION", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY")
    missing = [n for n in needed if not env.get(n)]
    if missing:
        raise ValueError("Missing S3 settings: " + ", ".join(missing))
    return S3Storage(
        env["S3_ENDPOINT"], env["S3_BUCKET"], env["S3_REGION"],
        env["S3_ACCESS_KEY_ID"], env["S3_SECRET_ACCESS_KEY"],
    )
