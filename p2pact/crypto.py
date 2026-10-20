"""Primitives: X25519, Ed25519, ChaCha20-Poly1305 (cryptography), BLAKE2s and HMAC (stdlib)."""
import base64
import hashlib
import hmac as _hmac
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def x25519_keypair(priv: bytes | None = None) -> tuple[bytes, bytes]:
    priv = priv or os.urandom(32)
    pub = X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub


def x25519(priv: bytes, pub: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


def ed25519_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False


def blake2s(*parts: bytes) -> bytes:
    h = hashlib.blake2s(digest_size=32)
    for p in parts:
        h.update(p)
    return h.digest()


def hmac(key: bytes, *parts: bytes) -> bytes:
    h = _hmac.new(key, digestmod=hashlib.blake2s)
    for p in parts:
        h.update(p)
    return h.digest()


def mac(key: bytes, label: str) -> bytes:
    """HMAC-BLAKE2s(key, label): relay channels and invite ids come from secrets."""
    return hmac(key, label.encode())


def _nonce(n: int) -> bytes:
    return b"\x00" * 4 + struct.pack("<Q", n)


def seal(key: bytes, n: int, ad: bytes, pt: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(_nonce(n), bytes(pt), bytes(ad))


def open_(key: bytes, n: int, ad: bytes, ct: bytes) -> bytes | None:
    try:
        return ChaCha20Poly1305(key).decrypt(_nonce(n), bytes(ct), bytes(ad))
    except (InvalidTag, ValueError):
        return None


def address(pub: bytes) -> str:
    """A device address: the first 16 bytes of BLAKE2s of its public key, lowercase base32."""
    return base64.b32encode(blake2s(pub)[:16]).decode().rstrip("=").lower()
