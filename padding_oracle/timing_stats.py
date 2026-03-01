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
    min_ms: float
    avg_ms: float
    max_ms: float


def _summarize(values: list[int]) -> Summary:
    if not values:
        return Summary(
            count=0,
            min_ms=0.0,
            avg_ms=0.0,
            max_ms=0.0,
        )
    ns_to_ms = 1_000_000.0
    return Summary(
        count=len(values),
        min_ms=min(values) / ns_to_ms,
        avg_ms=statistics.fmean(values) / ns_to_ms,
        max_ms=max(values) / ns_to_ms,
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
    print("step count min_ms avg_ms max_ms")
    for name in STEP_NAMES:
        stats = _summarize(rows[name])
        step_name = name[:-3] if name.endswith("_ns") else name
        print(
            f"{step_name} {stats.count} "
            f"{stats.min_ms:.6f} {stats.avg_ms:.6f} {stats.max_ms:.6f}"
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
