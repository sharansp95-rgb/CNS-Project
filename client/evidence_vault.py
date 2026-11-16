"""Python reference for the browser's password-encrypted vault package.

PBKDF2-SHA256 / 600000, 16 random salt bytes + purpose bytes, AES-256-GCM,
12-byte random IV, 16-byte tag. AAD binds the plaintext file SHA-256.
"""

import base64
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

FORMAT = "securechat-vault/v1"
PURPOSE = b"CNSProject evidence vault v1\x00"
ITERATIONS = 600000


def _key(password, salt):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=PURPOSE + salt, iterations=ITERATIONS
    ).derive(password.encode("utf-8"))


def encrypt_evidence(file_bytes, password):
    salt, nonce = os.urandom(16), os.urandom(12)
    digest = hashlib.sha256(file_bytes).hexdigest()
    ciphertext = AESGCM(_key(password, salt)).encrypt(
        nonce, file_bytes, (FORMAT + "\x00" + digest).encode("ascii")
    )
    enc = lambda b: base64.b64encode(b).decode("ascii")
    return dict(
        format=FORMAT,
        iterations=ITERATIONS,
        salt=enc(salt),
        nonce=enc(nonce),
        file_sha256=digest,
        ciphertext=enc(ciphertext),
    )


def decrypt_evidence(package, password):
    if package.get("format") != FORMAT or package.get("iterations") != ITERATIONS:
        raise ValueError("Unsupported vault format/parameters")
    dec = lambda name: base64.b64decode(package[name], validate=True)
    salt, nonce = dec("salt"), dec("nonce")
    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("Invalid vault salt/nonce")
    digest = package["file_sha256"]
    data = AESGCM(_key(password, salt)).decrypt(
        nonce, dec("ciphertext"), (FORMAT + "\x00" + digest).encode("ascii")
    )
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("File SHA-256 mismatch")
    return data
