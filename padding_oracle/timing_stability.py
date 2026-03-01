from __future__ import annotations

import argparse
import bisect
import statistics
from dataclasses import dataclass

from . import crypto, process, protocol, utils


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
        description="Measure task4-relevant latency stability over proxy jitter.",
    )
    parser.add_argument("--samples", type=int, default=10000, help="measured checks per class, per jitter")
    parser.add_argument("--warmup", type=int, default=200, help="unreported warmup checks per class")
    parser.add_argument("--jitters-ms", default="0,0.000001,0.000002,0.000003,0.000004")
    parser.add_argument("--base-delay-ms", type=float, default=0.0)
    parser.add_argument("--message", default="timing-stability-message")
    args = parser.parse_args()

    if args.samples < 1:
        raise ValueError("samples must be >= 1")
    if args.warmup < 0:
        raise ValueError("warmup must be >= 0")

    jitters_ms = utils.parse_csv_floats(args.jitters_ms)
    _ = utils.ms_to_seconds(args.base_delay_ms)
    for jitter in jitters_ms:
        _ = utils.ms_to_seconds(jitter)

    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)

    server_addr = process.free_local_addr()
    server_proc = process.start_self_process(
        [
            "server",
            "--addr",
            server_addr,
            "--enc-key",
            enc_key.hex(),
            "--mac-key",
            mac_key.hex(),
        ]
    )

    try:
        process.wait_for_tcp(server_addr, timeout=3.0)
        print(
            "jitter_ms class avg_ns median_ns p95_ns p99_ns stddev_ns "
            "avg_ms median_ms p95_ms p99_ms stddev_ms"
        )
        print(
            "jitter_ms separation_gap_ns separation_sigma_ns signal_to_noise cohen_d p(mac_bad>pad_bad)"
        )

        for i, jitter_ms in enumerate(jitters_ms):
            proxy_addr = process.free_local_addr()
            proxy_proc = process.start_self_process(
                [
                    "proxy",
                    "--listen",
                    proxy_addr,
                    "--target",
                    server_addr,
                    "--base-delay-ms",
                    f"{args.base_delay_ms}",
                    "--jitter-ms",
                    f"{jitter_ms}",
                    "--seed",
                    str(4242 + i),
                ]
            )
            try:
                process.wait_for_tcp(proxy_addr, timeout=3.0)
                with protocol.Client(proxy_addr, timeout=2.0) as client:
                    valid_ct = client.encrypt(args.message.encode("utf-8"))
                    mac_bad_ct = _tamper_mac(valid_ct)
                    pad_bad_ct = _ensure_invalid_padding(client, valid_ct)

                    ok_valid, _ = client.check(valid_ct)
                    ok_mac, _ = client.check(mac_bad_ct)
                    ok_pad, _ = client.check(pad_bad_ct)
                    if not ok_valid:
                        raise RuntimeError("valid sample is not valid")
                    if ok_mac:
                        raise RuntimeError("mac_bad sample unexpectedly valid")
                    if ok_pad:
                        raise RuntimeError("pad_bad sample unexpectedly valid")

                    valid_ns, mac_bad_ns, pad_bad_ns = _collect(
                        client=client,
                        valid_ct=valid_ct,
                        mac_bad_ct=mac_bad_ct,
                        pad_bad_ct=pad_bad_ct,
                        samples=args.samples,
                        warmup=args.warmup,
                    )

                valid_stats = _summarize(valid_ns)
                mac_bad_stats = _summarize(mac_bad_ns)
                pad_bad_stats = _summarize(pad_bad_ns)

                for label, stats in (
                    ("valid", valid_stats),
                    ("mac_bad", mac_bad_stats),
                    ("pad_bad", pad_bad_stats),
                ):
                    print(
                        f"{jitter_ms:.6f} {label} "
                        f"{stats.avg_ns:.2f} {stats.median_ns:.2f} {stats.p95_ns:.2f} {stats.p99_ns:.2f} {stats.stddev_ns:.2f} "
                        f"{stats.avg_ns/1_000_000.0:.6f} {stats.median_ns/1_000_000.0:.6f} "
                        f"{stats.p95_ns/1_000_000.0:.6f} {stats.p99_ns/1_000_000.0:.6f} {stats.stddev_ns/1_000_000.0:.6f}"
                    )

                gap = mac_bad_stats.avg_ns - pad_bad_stats.avg_ns
                separation_sigma = (mac_bad_stats.stddev_ns**2 + pad_bad_stats.stddev_ns**2) ** 0.5
                snr = _safe_div(gap, separation_sigma)
                pooled = _pooled_std(mac_bad_stats, pad_bad_stats)
                cohen_d = _safe_div(gap, pooled)
                p_mac_gt_pad = _p_greater(mac_bad_ns, pad_bad_ns)
                print(
                    f"{jitter_ms:.6f} sep "
                    f"{gap:.2f} {separation_sigma:.2f} {snr:.4f} {cohen_d:.4f} {p_mac_gt_pad:.6f}"
                )
            finally:
                process.stop_process(proxy_proc)
    finally:
        process.stop_process(server_proc)


if __name__ == "__main__":
    run()
