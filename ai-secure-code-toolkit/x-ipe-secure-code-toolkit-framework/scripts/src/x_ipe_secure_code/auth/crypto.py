"""Public-key-only cryptography: loading the trusted key and verifying signatures."""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class KeyFormatError(Exception):
    pass


def load_public(pem: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise KeyFormatError("trusted public key is not a valid PEM key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise KeyFormatError("trusted public key is not an Ed25519 key")
    return key


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_pem(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(raw_public(key)).hexdigest()[:32]


def verify_signature(key: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        key.verify(signature, data)
    except InvalidSignature:
        return False
    return True
