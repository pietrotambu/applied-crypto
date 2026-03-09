"""Service layer for task-specific vulnerable receivers."""
import hmac
import hashlib

from . import crypto

MAC_TAG_BYTES = 32

def compute_mac_tag(mac_key: bytes, msg: bytes) -> bytes:
    """Compute HMAC-SHA256 tag manually using hashlib.sha256."""
    block_size = 64  # SHA-256 block size in bytes

    key = mac_key
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))

    # HMAC mixes the block-sized key with two fixed pad constants defined by the standard:
    # 0x36 for the inner hash (ipad) and 0x5C for the outer hash (opad).
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)

    inner = hashlib.sha256(ipad + msg).digest()
    return hashlib.sha256(opad + inner).digest()


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
    ):
        self._enc_key = bytes(enc_key)
        self._mac_key = bytes(mac_key)
        # Validate key material path early.
        _ = compute_mac_tag(self._mac_key, b"")

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt `plaintext || MAC(plaintext)` under AES-CBC."""
        tag = compute_mac_tag(self._mac_key, plaintext)
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

        digest_len = MAC_TAG_BYTES
        if len(payload) >= digest_len:
            msg = payload[:-digest_len]
            tag = payload[-digest_len:]
        else:
            # Keep behavior explicit for malformed payloads shorter than a tag.
            msg = payload
            tag = b""

        expected = compute_mac_tag(self._mac_key, msg)
        if len(tag) != len(expected):
            return False
        return hmac.compare_digest(tag, expected)
