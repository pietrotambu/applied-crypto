from __future__ import annotations

import hashlib
import hmac

from . import crypto


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
    def __init__(self, enc_key: bytes, mac_key: bytes, mac_work: int = 4000):
        self._enc_key = bytes(enc_key)
        self._mac_key = bytes(mac_key)
        self._mac_work = max(0, int(mac_work))

    def encrypt(self, plaintext: bytes) -> bytes:
        tag = hmac.new(self._mac_key, plaintext, hashlib.sha256).digest()
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

        digest_len = hashlib.sha256().digest_size
        if len(payload) >= digest_len:
            msg = payload[:-digest_len]
            tag = payload[-digest_len:]
        else:
            msg = payload
            tag = b""

        for _ in range(self._mac_work):
            hmac.new(self._mac_key, msg, hashlib.sha256).digest()

        expected = hmac.new(self._mac_key, msg, hashlib.sha256).digest()
        if len(tag) != len(expected):
            return False
        return hmac.compare_digest(tag, expected)
