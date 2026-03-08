from __future__ import annotations

import argparse
import statistics
from dataclasses import dataclass

from . import crypto, process, protocol, utils


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
    client: protocol.Client,
    ciphertext: bytes,
    trials: int,
    warmup: int,
) -> list[int]:
    samples_ns: list[int] = []

    for _ in range(warmup):
        client.check(ciphertext)

    for _ in range(trials):
        _, delta_ns = client.check(ciphertext)
        samples_ns.append(delta_ns)
    return samples_ns


def _tamper_mac(ciphertext: bytes) -> bytes:
    # Flip one IV byte: padding stays valid but MAC should fail.
    if len(ciphertext) < 2 * crypto.BLOCK_SIZE:
        raise ValueError("ciphertext too short")
    out = bytearray(ciphertext)
    out[0] ^= 0x01
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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="padding-oracle-timing-stats",
        description="Compare task4 long path vs short path timings.",
    )
    parser.add_argument("--trials", type=int, default=10000, help="measured checks per path")
    parser.add_argument("--warmup", type=int, default=200, help="unreported warmup checks per path")
    parser.add_argument("--message-kb", type=float, default=1.0, help="random plaintext size in KB")
    parser.add_argument("--jitter-ms", type=float, default=0.0, help="proxy jitter")
    args = parser.parse_args()

    if args.trials < 1:
        raise ValueError("trials must be >= 1")
    if args.warmup < 0:
        raise ValueError("warmup must be >= 0")
    _ = utils.ms_to_seconds(args.jitter_ms)
    _ = utils.kb_to_bytes(args.message_kb)

    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)
    msg = utils.random_message_from_kb(args.message_kb)

    server_addr = process.free_local_addr()
    server_proc = process.start_self_process(utils.server_command_args(server_addr, enc_key, mac_key))

    proxy_addr = process.free_local_addr()
    proxy_proc = process.start_self_process(
        utils.proxy_command_args(
            listen_addr=proxy_addr,
            target_addr=server_addr,
            jitter_ms=args.jitter_ms,
        )
    )

    try:
        process.wait_for_tcp(server_addr, timeout=3.0)
        process.wait_for_tcp(proxy_addr, timeout=3.0)

        with protocol.Client(proxy_addr, timeout=2.0) as client:
            ciphertext = client.encrypt(msg)
            long_path_ct = _tamper_mac(ciphertext)
            short_path_ct = _ensure_invalid_padding(client, ciphertext)

            ok_long, _ = client.check(long_path_ct)
            ok_short, _ = client.check(short_path_ct)
            if ok_long:
                raise RuntimeError("long-path sample unexpectedly valid")
            if ok_short:
                raise RuntimeError("short-path sample unexpectedly valid")

            long_samples = _collect_samples(
                client=client,
                ciphertext=long_path_ct,
                trials=args.trials,
                warmup=args.warmup,
            )
            short_samples = _collect_samples(
                client=client,
                ciphertext=short_path_ct,
                trials=args.trials,
                warmup=args.warmup,
            )

        long_stats = _summarize(long_samples)
        short_stats = _summarize(short_samples)
        delta_avg_ms = long_stats.avg_ms - short_stats.avg_ms

        print(
            "flow4 path timing stats "
            f"(trials={args.trials}, warmup={args.warmup}, "
            f"jitter_ms={args.jitter_ms:.6f}, message_kb={args.message_kb})"
        )
        print("path min_ms avg_ms max_ms")
        print(
            f"long_journey "
            f"{long_stats.min_ms:.6f} {long_stats.avg_ms:.6f} {long_stats.max_ms:.6f}"
        )
        print(
            f"short_journey "
            f"{short_stats.min_ms:.6f} {short_stats.avg_ms:.6f} {short_stats.max_ms:.6f}"
        )
        print(f"delta_avg_ms(long-short) {delta_avg_ms:.6f}")
    finally:
        process.stop_process(proxy_proc)
        process.stop_process(server_proc)


if __name__ == "__main__":
    main()
