"""Low-level cryptographic helpers for CBC and PKCS#7 operations."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16


class InvalidPaddingError(ValueError):
    """Raised when PKCS#7 structure is invalid."""


class InvalidCiphertextError(ValueError):
    """Raised when ciphertext shape is incompatible with CBC decryption."""


def random_bytes(size: int) -> bytes:
    """Return `size` bytes of cryptographically secure randomness."""
    return os.urandom(size)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Apply PKCS#7 padding to `data` for the given block size."""
    if block_size <= 0:
        raise ValueError("block_size must be > 0")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Remove and validate PKCS#7 padding."""
    if block_size <= 0 or not data or len(data) % block_size != 0:
        raise InvalidPaddingError("invalid PKCS#7 padding")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size or pad_len > len(data):
        raise InvalidPaddingError("invalid PKCS#7 padding")
    if any(b != pad_len for b in data[-pad_len:]):
        raise InvalidPaddingError("invalid PKCS#7 padding")
    return data[:-pad_len]


def encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-CBC and return `IV || C`."""
    iv = os.urandom(BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv + encrypted


def decrypt_cbc_raw(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt `IV || C` and return padded plaintext bytes.

    CBC requires one IV block plus at least one ciphertext block.
    """
    if len(ciphertext) < 2 * BLOCK_SIZE or len(ciphertext) % BLOCK_SIZE != 0:
        raise InvalidCiphertextError("invalid ciphertext")
    iv = ciphertext[:BLOCK_SIZE]
    body = ciphertext[BLOCK_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(body) + decryptor.finalize()
