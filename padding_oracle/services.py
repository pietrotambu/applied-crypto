from __future__ import annotations

import hmac
import hashlib

from . import crypto

SHAKE256_RATE_BYTES = 136


def _hmac_shake256(key: bytes, msg: bytes, tag_bytes: int) -> bytes:
    # HMAC-style construction over SHAKE256 using sponge rate as block size.
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
    if mac_alg == "sha256":
        if mac_tag_bytes != 32:
            raise ValueError("sha256 mode requires mac_tag_bytes=32")
        return hmac.new(mac_key, msg, hashlib.sha256).digest()
    if mac_alg == "shake256":
        return _hmac_shake256(mac_key, msg, mac_tag_bytes)
    raise ValueError(f"unsupported mac_alg: {mac_alg}")


class BasicOracleService:
    def __init__(self, key: bytes):
        self._key = bytes(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        return crypto.encrypt_cbc(self._key, plaintext)

    def padding_oracle(self, ciphertext: bytes) -> bool:
        try:
            padded = crypto.decrypt_cbc_raw(self._key, ciphertext)
            crypto.pkcs7_unpad(padded, crypto.BLOCK_SIZE)
            return True
        except Exception:
            return False


class MacThenEncryptService:
    def __init__(
        self,
        enc_key: bytes,
        mac_key: bytes,
        timing_work_factor: int = 0,
        mac_alg: str = "sha256",
        mac_tag_bytes: int = 32,
    ):
        self._enc_key = bytes(enc_key)
        self._mac_key = bytes(mac_key)
        self._timing_work_factor = max(1, int(timing_work_factor))
        self._mac_alg = mac_alg
        self._mac_tag_bytes = int(mac_tag_bytes)
        if self._mac_tag_bytes < 1:
            raise ValueError("mac_tag_bytes must be >= 1")
        # Validate mode/size early.
        _ = compute_mac_tag(self._mac_alg, self._mac_key, b"", self._mac_tag_bytes)

    def encrypt(self, plaintext: bytes) -> bytes:
        tag = compute_mac_tag(self._mac_alg, self._mac_key, plaintext, self._mac_tag_bytes)
        payload = plaintext + tag
        return crypto.encrypt_cbc(self._enc_key, payload)

    def check(self, ciphertext: bytes) -> bool:
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
            msg = payload
            tag = b""

        if self._timing_work_factor == 1:
            expected = compute_mac_tag(self._mac_alg, self._mac_key, msg, self._mac_tag_bytes)
        else:
            expected = b""
            for _ in range(self._timing_work_factor):
                expected = compute_mac_tag(self._mac_alg, self._mac_key, msg, self._mac_tag_bytes)
        if len(tag) != len(expected):
            return False
        return hmac.compare_digest(tag, expected)
