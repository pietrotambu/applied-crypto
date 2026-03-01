from __future__ import annotations

import argparse
import statistics
from dataclasses import dataclass

from . import crypto, services

STEP_NAMES = (
    "decrypt_cbc_raw_ns",
    "pkcs7_unpad_ns",
    "hmac_sha256_ns",
    "compare_digest_ns",
    "total_ns",
)


@dataclass(frozen=True)
class Summary:
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
    sorted_values = sorted(values)
    rank = (len(sorted_values) - 1) * p
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    weight = rank - lo
    return float(sorted_values[lo] * (1.0 - weight) + sorted_values[hi] * weight)


def _summarize(values: list[int]) -> Summary:
    if not values:
        return Summary(
            count=0,
            min_ns=0,
            avg_ns=0.0,
            median_ns=0.0,
            p95_ns=0.0,
            p99_ns=0.0,
            max_ns=0,
            stddev_ns=0.0,
        )
    if len(values) == 1:
        return Summary(
            count=1,
            min_ns=values[0],
            avg_ns=float(values[0]),
            median_ns=float(values[0]),
            p95_ns=float(values[0]),
            p99_ns=float(values[0]),
            max_ns=values[0],
            stddev_ns=0.0,
        )
    return Summary(
        count=len(values),
        min_ns=min(values),
        avg_ns=statistics.fmean(values),
        median_ns=statistics.median(values),
        p95_ns=_percentile(values, 0.95),
        p99_ns=_percentile(values, 0.99),
        max_ns=max(values),
        stddev_ns=statistics.stdev(values),
    )


def _collect_samples(
    service: services.MacThenEncryptService,
    ciphertext: bytes,
    trials: int,
    warmup: int,
) -> tuple[int, dict[str, list[int]]]:
    rows: dict[str, list[int]] = {name: [] for name in STEP_NAMES}
    ok_count = 0

    for _ in range(warmup):
        service.check_with_timing(ciphertext)

    for _ in range(trials):
        ok, timing = service.check_with_timing(ciphertext)
        if ok:
            ok_count += 1
        data = timing.as_ns()
        for name in STEP_NAMES:
            rows[name].append(data[name])
    return ok_count, rows


def _print_report(title: str, ok_count: int, trials: int, rows: dict[str, list[int]]) -> None:
    print(title)
    print(f"checks_ok={ok_count}/{trials}")
    print(
        "step count min_ns avg_ns median_ns p95_ns p99_ns max_ns stddev_ns "
        "min_ms avg_ms median_ms p95_ms p99_ms max_ms stddev_ms"
    )
    for name in STEP_NAMES:
        stats = _summarize(rows[name])
        min_ms = stats.min_ns / 1_000_000.0
        avg_ms = stats.avg_ns / 1_000_000.0
        median_ms = stats.median_ns / 1_000_000.0
        p95_ms = stats.p95_ns / 1_000_000.0
        p99_ms = stats.p99_ns / 1_000_000.0
        max_ms = stats.max_ns / 1_000_000.0
        stddev_ms = stats.stddev_ns / 1_000_000.0
        print(
            f"{name} {stats.count} "
            f"{stats.min_ns} {stats.avg_ns:.2f} {stats.median_ns:.2f} "
            f"{stats.p95_ns:.2f} {stats.p99_ns:.2f} "
            f"{stats.max_ns} {stats.stddev_ns:.2f} "
            f"{min_ms:.6f} {avg_ms:.6f} {median_ms:.6f} "
            f"{p95_ms:.6f} {p99_ms:.6f} "
            f"{max_ms:.6f} {stddev_ms:.6f}"
        )


def _tampered_ciphertext(ciphertext: bytes) -> bytes:
    if len(ciphertext) < 2:
        raise ValueError("ciphertext too short to tamper")
    return ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="padding-oracle-timing-stats",
        description="Analyze check() timing breakdown statistics over many retries.",
    )
    parser.add_argument("--trials", type=int, default=5000, help="number of measured check() calls")
    parser.add_argument("--warmup", type=int, default=200, help="unreported warmup check() calls")
    parser.add_argument("--message", default="timing-stats-message", help="plaintext used for encrypted sample")
    parser.add_argument(
        "--mode",
        choices=("valid", "invalid", "both"),
        default="both",
        help="whether to measure valid, tampered-invalid, or both ciphertext paths",
    )
    args = parser.parse_args()

    if args.trials < 1:
        raise ValueError("trials must be >= 1")
    if args.warmup < 0:
        raise ValueError("warmup must be >= 0")

    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)
    service = services.MacThenEncryptService(enc_key, mac_key)
    ciphertext = service.encrypt(args.message.encode("utf-8"))
    bad_ciphertext = _tampered_ciphertext(ciphertext)

    if args.mode in ("valid", "both"):
        ok_count, rows = _collect_samples(service, ciphertext, args.trials, args.warmup)
        _print_report(
            title=f"valid ciphertext timing stats (trials={args.trials}, warmup={args.warmup})",
            ok_count=ok_count,
            trials=args.trials,
            rows=rows,
        )
        if args.mode == "both":
            print("")

    if args.mode in ("invalid", "both"):
        ok_count, rows = _collect_samples(service, bad_ciphertext, args.trials, args.warmup)
        _print_report(
            title=f"tampered ciphertext timing stats (trials={args.trials}, warmup={args.warmup})",
            ok_count=ok_count,
            trials=args.trials,
            rows=rows,
        )


if __name__ == "__main__":
    main()
