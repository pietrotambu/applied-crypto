from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import crypto


class AttackError(RuntimeError):
    pass


BoolOracle = Callable[[bytes], bool]
TimingOracle = Callable[[bytes], int]


def recover_block_boolean(prev: bytes, curr: bytes, oracle: BoolOracle) -> tuple[bytes, int]:
    if len(prev) != crypto.BLOCK_SIZE or len(curr) != crypto.BLOCK_SIZE:
        raise AttackError("recover_block_boolean requires two 16-byte blocks")

    intermediate = bytearray(crypto.BLOCK_SIZE)
    plaintext = bytearray(crypto.BLOCK_SIZE)
    queries = 0

    for pos in range(crypto.BLOCK_SIZE - 1, -1, -1):
        pad = crypto.BLOCK_SIZE - pos
        base = bytearray(prev)
        for j in range(crypto.BLOCK_SIZE - 1, pos, -1):
            base[j] = intermediate[j] ^ pad

        found = False
        for guess in range(256):
            candidate_prev = bytearray(base)
            candidate_prev[pos] = guess
            forged = bytes(candidate_prev) + curr

            queries += 1
            if not oracle(forged):
                continue

            if pos == crypto.BLOCK_SIZE - 1:
                probe = bytearray(candidate_prev)
                probe[pos - 1] ^= 0x01
                queries += 1
                if not oracle(bytes(probe) + curr):
                    continue

            intermediate[pos] = guess ^ pad
            plaintext[pos] = intermediate[pos] ^ prev[pos]
            found = True
            break

        if not found:
            raise AttackError(f"no valid byte candidate found at position {pos}")

    return bytes(plaintext), queries


def recover_plaintext_boolean(ciphertext: bytes, oracle: BoolOracle) -> tuple[bytes, int]:
    if len(ciphertext) < 2 * crypto.BLOCK_SIZE or len(ciphertext) % crypto.BLOCK_SIZE != 0:
        raise AttackError("ciphertext must include IV and be a multiple of 16 bytes")

    blocks = [ciphertext[i : i + crypto.BLOCK_SIZE] for i in range(0, len(ciphertext), crypto.BLOCK_SIZE)]
    out = bytearray()
    total_queries = 0

    for i in range(1, len(blocks)):
        plain_block, q = recover_block_boolean(blocks[i - 1], blocks[i], oracle)
        total_queries += q
        out.extend(plain_block)

    return crypto.pkcs7_unpad(bytes(out), crypto.BLOCK_SIZE), total_queries


@dataclass
class TimingConfig:
    initial_samples: int = 1
    refine_samples: int = 4
    top_candidates: int = 6

    def normalized(self) -> "TimingConfig":
        return TimingConfig(
            initial_samples=max(1, int(self.initial_samples)),
            refine_samples=max(1, int(self.refine_samples)),
            top_candidates=min(256, max(1, int(self.top_candidates))),
        )


@dataclass
class Score:
    guess: int
    total: int
    samples: int
    forged: bytes

    def avg(self) -> float:
        return self.total / self.samples


def recover_block_timing(prev: bytes, curr: bytes, oracle: TimingOracle, config: TimingConfig) -> tuple[bytes, int]:
    cfg = config.normalized()
    if len(prev) != crypto.BLOCK_SIZE or len(curr) != crypto.BLOCK_SIZE:
        raise AttackError("recover_block_timing requires two 16-byte blocks")

    intermediate = bytearray(crypto.BLOCK_SIZE)
    plaintext = bytearray(crypto.BLOCK_SIZE)
    queries = 0

    for pos in range(crypto.BLOCK_SIZE - 1, -1, -1):
        pad = crypto.BLOCK_SIZE - pos
        base = bytearray(prev)
        for j in range(crypto.BLOCK_SIZE - 1, pos, -1):
            base[j] = intermediate[j] ^ pad

        scores: list[Score] = []
        for guess in range(256):
            candidate_prev = bytearray(base)
            candidate_prev[pos] = guess
            forged = bytes(candidate_prev) + curr

            total = _sample_duration_ns(oracle, forged, cfg.initial_samples)
            queries += cfg.initial_samples
            scores.append(Score(guess=guess, total=total, samples=cfg.initial_samples, forged=forged))

        scores.sort(key=lambda s: s.avg(), reverse=True)
        limit = min(cfg.top_candidates, len(scores))

        for i in range(limit):
            extra = _sample_duration_ns(oracle, scores[i].forged, cfg.refine_samples)
            queries += cfg.refine_samples
            scores[i].total += extra
            scores[i].samples += cfg.refine_samples

        scores.sort(key=lambda s: s.avg(), reverse=True)
        best_guess = scores[0].guess

        intermediate[pos] = best_guess ^ pad
        plaintext[pos] = intermediate[pos] ^ prev[pos]

    return bytes(plaintext), queries


def recover_ciphertext_block_timing(
    ciphertext: bytes,
    block_index: int,
    oracle: TimingOracle,
    config: TimingConfig,
) -> tuple[bytes, int]:
    if len(ciphertext) < 2 * crypto.BLOCK_SIZE or len(ciphertext) % crypto.BLOCK_SIZE != 0:
        raise AttackError("ciphertext must include IV and be a multiple of 16 bytes")

    num_blocks = len(ciphertext) // crypto.BLOCK_SIZE
    if block_index < 1 or block_index >= num_blocks:
        raise AttackError(f"block index {block_index} out of range")

    prev = ciphertext[(block_index - 1) * crypto.BLOCK_SIZE : block_index * crypto.BLOCK_SIZE]
    curr = ciphertext[block_index * crypto.BLOCK_SIZE : (block_index + 1) * crypto.BLOCK_SIZE]
    return recover_block_timing(prev, curr, oracle, config)


def _sample_duration_ns(oracle: TimingOracle, ciphertext: bytes, samples: int) -> int:
    total = 0
    for _ in range(samples):
        total += int(oracle(ciphertext))
    return total
