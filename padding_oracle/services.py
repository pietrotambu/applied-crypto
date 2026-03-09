"""Service layer for task-specific vulnerable receivers."""

from __future__ import annotations

import hmac
import hashlib

from . import crypto

SHAKE256_RATE_BYTES = 136


def _hmac_shake256(key: bytes, msg: bytes, tag_bytes: int) -> bytes:
    """HMAC-style construction over SHAKE256 using sponge rate as block size."""
    if tag_bytes < 1:
        raise ValueError("mac_tag_bytes must be >= 1")

    if len(key) > SHAKE256_RATE_BYTES:
        key_block = hashlib.shake_256(key).digest(SHAKE256_RATE_BYTES)
    else:
        key_block = key
    key_block = key_block.ljust(SHAKE256_RATE_BYTES, b"\x00")

    ipad = bytes((b ^ 0x36) for b in key_block)
    opad = bytes((b ^ 0x5C) for b in key_block)

    inner = hashlib.shake_256(ipad + msg).digest(tag_bytes)
    return hashlib.shake_256(opad + inner).digest(tag_bytes)


def compute_mac_tag(
    mac_alg: str,
    mac_key: bytes,
    msg: bytes,
    mac_tag_bytes: int = 32,
) -> bytes:
    """Compute MAC tag for the supported algorithm choices."""
    if mac_alg == "sha256":
        if mac_tag_bytes != 32:
            raise ValueError("sha256 mode requires mac_tag_bytes=32")
        return hmac.new(mac_key, msg, hashlib.sha256).digest()
    if mac_alg == "shake256":
        return _hmac_shake256(mac_key, msg, mac_tag_bytes)
    raise ValueError(f"unsupported mac_alg: {mac_alg}")


class BasicOracleService:
    """Task-2 service exposing encryption and a boolean padding oracle."""

    def __init__(self, key: bytes):
        self._key = bytes(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext under AES-CBC."""
        return crypto.encrypt_cbc(self._key, plaintext)

    def padding_oracle(self, ciphertext: bytes) -> bool:
        """Return whether ciphertext decrypts to valid PKCS#7 padding."""
        try:
            padded = crypto.decrypt_cbc_raw(self._key, ciphertext)
            crypto.pkcs7_unpad(padded, crypto.BLOCK_SIZE)
            return True
        except Exception:
            return False


class MacThenEncryptService:
    """Task-3/4 service with MAC-then-encrypt and timing-different failure paths."""

    def __init__(
        self,
        enc_key: bytes,
        mac_key: bytes,
        mac_alg: str = "sha256",
        mac_tag_bytes: int = 32,
    ):
        self._enc_key = bytes(enc_key)
        self._mac_key = bytes(mac_key)
        self._mac_alg = mac_alg
        self._mac_tag_bytes = int(mac_tag_bytes)
        if self._mac_tag_bytes < 1:
            raise ValueError("mac_tag_bytes must be >= 1")
        # Validate mode/size early.
        _ = compute_mac_tag(self._mac_alg, self._mac_key, b"", self._mac_tag_bytes)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt `plaintext || MAC(plaintext)` under AES-CBC."""
        tag = compute_mac_tag(self._mac_alg, self._mac_key, plaintext, self._mac_tag_bytes)
        payload = plaintext + tag
        return crypto.encrypt_cbc(self._enc_key, payload)

    def check(self, ciphertext: bytes) -> bool:
        """Validate ciphertext by checking padding first, then MAC."""
        try:
            padded = crypto.decrypt_cbc_raw(self._enc_key, ciphertext)
        except Exception:
            return False

        try:
            payload = crypto.pkcs7_unpad(padded, crypto.BLOCK_SIZE)
        except Exception:
            return False

        digest_len = self._mac_tag_bytes
        if len(payload) >= digest_len:
            msg = payload[:-digest_len]
            tag = payload[-digest_len:]
        else:
            # Keep behavior explicit for malformed payloads shorter than a tag.
            msg = payload
            tag = b""

        expected = compute_mac_tag(self._mac_alg, self._mac_key, msg, self._mac_tag_bytes)
        if len(tag) != len(expected):
            return False
        return hmac.compare_digest(tag, expected)
