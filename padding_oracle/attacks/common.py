"""Shared exception types and CBC byte-forging helpers for attacks."""

from __future__ import annotations

from typing import Callable

from .. import crypto


class AttackError(RuntimeError):
    """Raised when an attack cannot recover plaintext under current assumptions."""


# Oracle types shared by attack implementations.
BoolOracle = Callable[[bytes], bool]
TimingOracle = Callable[[bytes], int]


def require_two_blocks(prev: bytes, curr: bytes) -> None:
    """Validate a two-block CBC attack input (`prev`, `curr`)."""
    if len(prev) != crypto.BLOCK_SIZE or len(curr) != crypto.BLOCK_SIZE:
        raise AttackError("attack requires two 16-byte blocks")


def require_ciphertext_with_iv(ciphertext: bytes) -> int:
    """Validate `IV || C` shape and return block count."""
    if len(ciphertext) < 2 * crypto.BLOCK_SIZE or len(ciphertext) % crypto.BLOCK_SIZE != 0:
        raise AttackError("ciphertext must include IV and be a multiple of 16 bytes")
    return len(ciphertext) // crypto.BLOCK_SIZE


def build_byte_recovery_base(
    prev: bytes,
    intermediate: bytearray,
    pos: int,
) -> tuple[int, bytearray]:
    """Return `(pad, base_prev_block)` with solved suffix rewritten for PKCS#7 `pad`."""
    pad = crypto.BLOCK_SIZE - pos
    base = bytearray(prev)
    for j in range(crypto.BLOCK_SIZE - 1, pos, -1):
        base[j] = intermediate[j] ^ pad
    return pad, base


def forge_candidate(
    base_prev: bytearray,
    pos: int,
    guess: int,
    curr: bytes,
    prefix: bytes = b"",
) -> tuple[bytearray, bytes]:
    """Forge a candidate ciphertext for one byte guess and return `(prev, ciphertext)`."""
    candidate_prev = bytearray(base_prev)
    candidate_prev[pos] = guess
    forged = prefix + bytes(candidate_prev) + curr
    return candidate_prev, forged


def decode_guess_byte(prev_byte: int, guess: int, pad: int) -> tuple[int, int]:
    """Convert a winning guess into `(intermediate_byte, plaintext_byte)`."""
    intermediate_byte = guess ^ pad
    plaintext_byte = intermediate_byte ^ prev_byte
    return intermediate_byte, plaintext_byte
