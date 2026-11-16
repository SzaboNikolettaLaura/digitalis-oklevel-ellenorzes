"""
Kriptográfiai modul a Credential Verifier rendszerhez.

- Hash-képzés: BLAKE2b (32 bájtos kimenet) a dokumentum determinisztikus JSON-jén.
- Digitális aláírás: Ed25519 (a `cryptography` csomagból).
"""

import json
from hashlib import blake2b
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

HASH_SIZE = 32  # bájt -> 256 bites hash, ugyanakkora, mint a SHA-256


def blake_hash(data: bytes) -> bytes:
    """Nyers bájtsorozat BLAKE2b hash-e (32 bájt)."""
    return blake2b(data, digest_size=HASH_SIZE).digest()


def generate_key_pair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Új Ed25519 kulcspár generálása a kibocsátó (egyetem) számára.

    Returns:
        (privát kulcs, publikus kulcs) pár.
    """
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_hex(public_key: Ed25519PublicKey) -> str:
    """A publikus kulcs nyers (32 bájtos) alakja hexában – kiíratáshoz, publikáláshoz."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def canonical_json(doc_dict: dict[str, Any]) -> bytes:
    """A dokumentum determinisztikus JSON-szerializálása.

    Rendezett kulcsok, szóközök nélküli elválasztók és UTF-8 kódolás,
    így ugyanaz a tartalom mindig ugyanazt a bájtsorozatot adja.
    """
    return json.dumps(
        doc_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=False
    ).encode('utf-8')


def hash_document(doc_dict: dict[str, Any]) -> bytes:
    """Az oklevél (dict) BLAKE2b hash-e a kanonikus JSON alakból."""
    return blake_hash(canonical_json(doc_dict))


def sign_hash(private_key: Ed25519PrivateKey, doc_hash: bytes) -> bytes:
    """Digitális aláírás készítése a dokumentum hash-ére.

    Returns:
        64 bájtos Ed25519 aláírás.
    """
    return private_key.sign(doc_hash)


def verify_signature(public_key: Ed25519PublicKey, doc_hash: bytes,
                     signature: bytes) -> bool:
    """Az aláírás ellenőrzése a kibocsátó publikus kulcsával.

    Returns:
        True, ha az aláírás érvényes az adott hash-re, különben False.
    """
    try:
        public_key.verify(signature, doc_hash)
        return True
    except InvalidSignature:
        return False
