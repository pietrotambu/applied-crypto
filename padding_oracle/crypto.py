from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16


class InvalidPaddingError(ValueError):
    pass


class InvalidCiphertextError(ValueError):
    pass


def random_bytes(size: int) -> bytes:
    return os.urandom(size)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0:
        raise ValueError("block_size must be > 0")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or not data or len(data) % block_size != 0:
        raise InvalidPaddingError("invalid PKCS#7 padding")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size or pad_len > len(data):
        raise InvalidPaddingError("invalid PKCS#7 padding")
    if any(b != pad_len for b in data[-pad_len:]):
        raise InvalidPaddingError("invalid PKCS#7 padding")
    return data[:-pad_len]


def encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv + encrypted


def decrypt_cbc_raw(key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) < 2 * BLOCK_SIZE or len(ciphertext) % BLOCK_SIZE != 0:
        raise InvalidCiphertextError("invalid ciphertext")
    iv = ciphertext[:BLOCK_SIZE]
    body = ciphertext[BLOCK_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(body) + decryptor.finalize()
