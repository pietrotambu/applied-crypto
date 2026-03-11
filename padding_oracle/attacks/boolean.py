"""Classic boolean padding-oracle attack implementation."""

from __future__ import annotations

from .. import crypto
from .common import (
    AttackError,
    BoolOracle,
    build_byte_recovery_base,
    decode_guess_byte,
    forge_candidate,
    require_ciphertext_with_iv,
    require_two_blocks,
)


def recover_block_boolean(prev: bytes, curr: bytes, oracle: BoolOracle) -> tuple[bytes, int]:
    """Recover one plaintext block with a boolean PKCS#7 padding oracle.

    Args:
        prev: Previous ciphertext block (or IV).
        curr: Ciphertext block to decrypt.
        oracle: Callable returning whether padding is valid.

    Returns:
        Tuple of recovered plaintext block and number of oracle queries.
    """
    require_two_blocks(prev, curr)

    intermediate = bytearray(crypto.BLOCK_SIZE)
    plaintext = bytearray(crypto.BLOCK_SIZE)
    queries = 0

    for pos in range(crypto.BLOCK_SIZE - 1, -1, -1):
        # Rewrite already-solved suffix bytes so they decrypt to the current pad.
        pad, base = build_byte_recovery_base(prev, intermediate, pos)

        found = False
        for guess in range(256):
            candidate_prev, forged = forge_candidate(base, pos, guess, curr)

            queries += 1
            if not oracle(forged):
                continue

            if pos == crypto.BLOCK_SIZE - 1:
                # For pad=1 a positive can be caused by pre-existing padding.
                # Flip a neighbor byte and re-check to keep only true pad=1 hits.
                probe = bytearray(candidate_prev)
                probe[pos - 1] ^= 0x01
                queries += 1
                if not oracle(bytes(probe) + curr):
                    continue

            # D[pos] = C'_{i-1}[pos] XOR pad; then P[pos] = D[pos] XOR C_{i-1}[pos].
            intermediate[pos], plaintext[pos] = decode_guess_byte(prev[pos], guess, pad)
            found = True
            break

        if not found:
            raise AttackError(f"no valid byte candidate found at position {pos}")

    return bytes(plaintext), queries


def recover_plaintext_boolean(ciphertext: bytes, oracle: BoolOracle) -> tuple[bytes, int]:
    """Recover full plaintext by attacking each CBC block with a boolean oracle."""
    _ = require_ciphertext_with_iv(ciphertext)

    blocks = [ciphertext[i : i + crypto.BLOCK_SIZE] for i in range(0, len(ciphertext), crypto.BLOCK_SIZE)]
    out = bytearray()
    total_queries = 0

    for i in range(1, len(blocks)):
        plain_block, q = recover_block_boolean(blocks[i - 1], blocks[i], oracle)
        total_queries += q
        out.extend(plain_block)

    return crypto.pkcs7_unpad(bytes(out), crypto.BLOCK_SIZE), total_queries
