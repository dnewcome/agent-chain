"""Ed25519 CA key management. Mirrors energy-secops' TrustedOracleBackend.

v0: the recorder's own key signs every step. When providers start signing
per-call receipts, we keep this CA (it seals the chain itself) and add
`provider_receipt` payload to LLM steps.
"""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import content_hash

DEFAULT_KEY_PATH = Path.home() / ".work-chain" / "ca.key"


def _load_or_create_key(key_path: Path) -> Ed25519PrivateKey:
    if key_path.exists():
        return serialization.load_pem_private_key(key_path.read_bytes(), password=None)  # type: ignore[return-value]
    key = Ed25519PrivateKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.with_suffix(".pub").write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key


def _key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return content_hash(raw)[:19]  # "sha256:" + 12 hex


class Signer:
    backend = "trusted-oracle"

    def __init__(self, key_path: str | Path = DEFAULT_KEY_PATH):
        self._key = _load_or_create_key(Path(key_path))
        self._key_id = _key_id(self._key.public_key())

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, payload: bytes) -> str:
        return self._key.sign(payload).hex()

    def verify(self, payload: bytes, signature_hex: str, key_id: str) -> bool:
        if key_id != self._key_id:
            return False
        try:
            self._key.public_key().verify(bytes.fromhex(signature_hex), payload)
            return True
        except Exception:
            return False
