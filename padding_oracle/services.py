from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import time

from . import crypto


@dataclass(frozen=True)
class CheckTiming:
    decrypt_cbc_raw_ns: int = 0
    pkcs7_unpad_ns: int = 0
    hmac_sha256_ns: int = 0
    compare_digest_ns: int = 0
    total_ns: int = 0

    def as_ns(self) -> dict[str, int]:
        return {
            "decrypt_cbc_raw_ns": self.decrypt_cbc_raw_ns,
            "pkcs7_unpad_ns": self.pkcs7_unpad_ns,
            "hmac_sha256_ns": self.hmac_sha256_ns,
            "compare_digest_ns": self.compare_digest_ns,
            "total_ns": self.total_ns,
        }

    def as_ms(self) -> dict[str, float]:
        ns = self.as_ns()
        return {k.replace("_ns", "_ms"): (v / 1_000_000.0) for k, v in ns.items()}


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
    def __init__(self, enc_key: bytes, mac_key: bytes):
        self._enc_key = bytes(enc_key)
        self._mac_key = bytes(mac_key)

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

        expected = hmac.new(self._mac_key, msg, hashlib.sha256).digest()
        if len(tag) != len(expected):
            return False
        return hmac.compare_digest(tag, expected)

    def check_with_timing(self, ciphertext: bytes) -> tuple[bool, CheckTiming]:
        total_start = time.perf_counter_ns()
        decrypt_cbc_raw_ns = 0
        pkcs7_unpad_ns = 0
        hmac_sha256_ns = 0
        compare_digest_ns = 0

        step_start = time.perf_counter_ns()
        try:
            padded = crypto.decrypt_cbc_raw(self._enc_key, ciphertext)
        except Exception:
            decrypt_cbc_raw_ns = time.perf_counter_ns() - step_start
            return False, CheckTiming(
                decrypt_cbc_raw_ns=decrypt_cbc_raw_ns,
                pkcs7_unpad_ns=pkcs7_unpad_ns,
                hmac_sha256_ns=hmac_sha256_ns,
                compare_digest_ns=compare_digest_ns,
                total_ns=(time.perf_counter_ns() - total_start),
            )
        decrypt_cbc_raw_ns = time.perf_counter_ns() - step_start

        step_start = time.perf_counter_ns()
        try:
            payload = crypto.pkcs7_unpad(padded, crypto.BLOCK_SIZE)
        except Exception:
            pkcs7_unpad_ns = time.perf_counter_ns() - step_start
            return False, CheckTiming(
                decrypt_cbc_raw_ns=decrypt_cbc_raw_ns,
                pkcs7_unpad_ns=pkcs7_unpad_ns,
                hmac_sha256_ns=hmac_sha256_ns,
                compare_digest_ns=compare_digest_ns,
                total_ns=(time.perf_counter_ns() - total_start),
            )
        pkcs7_unpad_ns = time.perf_counter_ns() - step_start

        digest_len = hashlib.sha256().digest_size
        if len(payload) >= digest_len:
            msg = payload[:-digest_len]
            tag = payload[-digest_len:]
        else:
            msg = payload
            tag = b""

        step_start = time.perf_counter_ns()
        expected = hmac.new(self._mac_key, msg, hashlib.sha256).digest()
        hmac_sha256_ns = time.perf_counter_ns() - step_start

        step_start = time.perf_counter_ns()
        if len(tag) != len(expected):
            compare_digest_ns = time.perf_counter_ns() - step_start
            return False, CheckTiming(
                decrypt_cbc_raw_ns=decrypt_cbc_raw_ns,
                pkcs7_unpad_ns=pkcs7_unpad_ns,
                hmac_sha256_ns=hmac_sha256_ns,
                compare_digest_ns=compare_digest_ns,
                total_ns=(time.perf_counter_ns() - total_start),
            )
        ok = hmac.compare_digest(tag, expected)
        compare_digest_ns = time.perf_counter_ns() - step_start

        return ok, CheckTiming(
            decrypt_cbc_raw_ns=decrypt_cbc_raw_ns,
            pkcs7_unpad_ns=pkcs7_unpad_ns,
            hmac_sha256_ns=hmac_sha256_ns,
            compare_digest_ns=compare_digest_ns,
            total_ns=(time.perf_counter_ns() - total_start),
        )
