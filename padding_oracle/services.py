from __future__ import annotations

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
