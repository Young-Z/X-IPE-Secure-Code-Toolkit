"""Signing-key handling. Only authorization init, re-authorization and revoke import this."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class WrongPassphrase(Exception):
    pass


def generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def encrypt(key: Ed25519PrivateKey, passphrase: str) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )


def decrypt(pem: bytes, passphrase: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=passphrase.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise WrongPassphrase("passphrase does not unlock the signing key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise WrongPassphrase("signing key is not an Ed25519 key")
    return key


def sign(key: Ed25519PrivateKey, data: bytes) -> bytes:
    return key.sign(data)
