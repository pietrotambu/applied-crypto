from __future__ import annotations

import argparse
import bisect
import statistics
from dataclasses import dataclass
import time

from . import attacks, crypto, process, protocol, utils


@dataclass(frozen=True)
class DistStats:
    count: int
    min_ns: int
    avg_ns: float
    median_ns: float
    p95_ns: float
    p99_ns: float
    max_ns: int
    stddev_ns: float


def _percentile(values: list[int], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    xs = sorted(values)
    rank = (len(xs) - 1) * p
    lo = int(rank)
    hi = min(lo + 1, len(xs) - 1)
    weight = rank - lo
    return float(xs[lo] * (1.0 - weight) + xs[hi] * weight)


def _summarize(values: list[int]) -> DistStats:
    if not values:
        return DistStats(0, 0, 0.0, 0.0, 0.0, 0.0, 0, 0.0)
    if len(values) == 1:
        only = values[0]
        return DistStats(1, only, float(only), float(only), float(only), float(only), only, 0.0)
    return DistStats(
        count=len(values),
        min_ns=min(values),
        avg_ns=statistics.fmean(values),
        median_ns=statistics.median(values),
        p95_ns=_percentile(values, 0.95),
        p99_ns=_percentile(values, 0.99),
        max_ns=max(values),
        stddev_ns=statistics.stdev(values),
    )


def _p_greater(a: list[int], b: list[int]) -> float:
    if not a or not b:
        return 0.0
    ys = sorted(b)
    less = 0
    equal = 0
    for x in a:
        lo = bisect.bisect_left(ys, x)
        hi = bisect.bisect_right(ys, x)
        less += lo
        equal += (hi - lo)
    total = len(a) * len(b)
    return (less + 0.5 * equal) / total


def _tamper_mac(ciphertext: bytes) -> bytes:
    if len(ciphertext) < crypto.BLOCK_SIZE * 2:
        raise ValueError("ciphertext too short")
    out = bytearray(ciphertext)
    out[0] ^= 0x01  # flip IV byte -> preserves padding, invalidates MAC
    return bytes(out)


def _tamper_padding(ciphertext: bytes) -> bytes:
    if len(ciphertext) < 2:
        raise ValueError("ciphertext too short")
    out = bytearray(ciphertext)
    out[-1] ^= 0x01
    return bytes(out)


def _ensure_invalid_padding(client: protocol.Client, base_ct: bytes) -> bytes:
    candidate = _tamper_padding(base_ct)
    ok, _ = client.check(candidate)
    if not ok:
        return candidate
    for mask in range(2, 256):
        out = bytearray(base_ct)
        out[-1] ^= mask
        ok, _ = client.check(bytes(out))
        if not ok:
            return bytes(out)
    raise RuntimeError("failed to produce invalid-padding sample")


def _collect(
    client: protocol.Client,
    valid_ct: bytes,
    mac_bad_ct: bytes,
    pad_bad_ct: bytes,
    samples: int,
    warmup: int,
) -> tuple[list[int], list[int], list[int]]:
    valid_ns: list[int] = []
    mac_bad_ns: list[int] = []
    pad_bad_ns: list[int] = []

    for _ in range(warmup):
        client.check(valid_ct)
        client.check(mac_bad_ct)
        client.check(pad_bad_ct)

    for _ in range(samples):
        _, dt = client.check(valid_ct)
        valid_ns.append(dt)
        _, dt = client.check(mac_bad_ct)
        mac_bad_ns.append(dt)
        _, dt = client.check(pad_bad_ct)
        pad_bad_ns.append(dt)

    return valid_ns, mac_bad_ns, pad_bad_ns


def _pooled_std(a: DistStats, b: DistStats) -> float:
    if a.count < 2 or b.count < 2:
        return 0.0
    num = ((a.count - 1) * (a.stddev_ns**2)) + ((b.count - 1) * (b.stddev_ns**2))
    den = a.count + b.count - 2
    return (num / den) ** 0.5


def _safe_div(num: float, den: float) -> float:
    if den == 0.0:
        return 0.0
    return num / den


def run() -> None:
    parser = argparse.ArgumentParser(
        prog="padding-oracle-timing-stability",
        description="Measure task4-like timing-attack robustness over proxy jitter.",
    )
    parser.add_argument("--trials", type=int, default=10, help="attack trials per jitter")
    parser.add_argument("--block-index", type=int, default=1)
    parser.add_argument("--initial-samples", type=int, default=32)
    parser.add_argument("--refine-samples", type=int, default=128)
    parser.add_argument("--top-k", type=int, default=16)
    parser.add_argument("--jitters-ms", default="0,0.000001,0.000002,0.000003,0.000004")
    parser.add_argument("--base-delay-ms", type=float, default=0.0)
    parser.add_argument("--message", default="timing-stability-message")
    args = parser.parse_args()

    if args.trials < 1:
        raise ValueError("trials must be >= 1")

    jitters_ms = utils.parse_csv_floats(args.jitters_ms)
    _ = utils.ms_to_seconds(args.base_delay_ms)
    for jitter in jitters_ms:
        _ = utils.ms_to_seconds(jitter)

    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)
    msg = args.message.encode("utf-8")
    expected = utils.expected_payload_block(msg, mac_key, args.block_index)
    cfg = attacks.TimingConfig(
        initial_samples=args.initial_samples,
        refine_samples=args.refine_samples,
        top_candidates=args.top_k,
    )

    server_addr = process.free_local_addr()
    server_proc = process.start_self_process(utils.server_command_args(server_addr, enc_key, mac_key))

    try:
        process.wait_for_tcp(server_addr, timeout=3.0)
        print(
            "jitter_ms success_rate avg_queries avg_elapsed_ms completed_trials error_trials"
        )

        for jitter_ms in jitters_ms:
            proxy_addr = process.free_local_addr()
            proxy_proc = process.start_self_process(
                utils.proxy_command_args(
                    listen_addr=proxy_addr,
                    target_addr=server_addr,
                    base_delay_ms=args.base_delay_ms,
                    jitter_ms=jitter_ms,
                )
            )
            try:
                process.wait_for_tcp(proxy_addr, timeout=3.0)
                success = 0
                total_queries = 0
                total_elapsed_ms = 0.0
                completed_trials = 0
                error_trials = 0

                for _ in range(args.trials):
                    try:
                        with protocol.Client(proxy_addr, timeout=2.0) as client:
                            ciphertext = client.encrypt(msg)

                            def oracle(candidate: bytes) -> int:
                                _, delta_ns = client.check(candidate)
                                return delta_ns

                            start_ns = time.perf_counter_ns()
                            recovered, queries = attacks.recover_ciphertext_block_timing(
                                ciphertext=ciphertext,
                                block_index=args.block_index,
                                oracle=oracle,
                                config=cfg,
                            )
                            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                            total_elapsed_ms += elapsed_ms
                            total_queries += queries
                            completed_trials += 1
                            if recovered == expected:
                                success += 1
                    except Exception:
                        error_trials += 1

                success_rate = success / args.trials
                if completed_trials > 0:
                    avg_queries = total_queries / completed_trials
                    avg_elapsed_ms = total_elapsed_ms / completed_trials
                else:
                    avg_queries = float("nan")
                    avg_elapsed_ms = float("nan")
                print(
                    f"{jitter_ms:.6f} {success_rate:.2f} {avg_queries:.1f} {avg_elapsed_ms:.2f} "
                    f"{completed_trials} {error_trials}"
                )
            finally:
                process.stop_process(proxy_proc)
    finally:
        process.stop_process(server_proc)


if __name__ == "__main__":
    run()
