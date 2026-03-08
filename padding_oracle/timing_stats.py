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
    # Flip a byte in the block before the last block. This mirrors the
    # last-block attack shape while keeping full-ciphertext context.
    if len(ciphertext) < 2 * crypto.BLOCK_SIZE:
        raise ValueError("ciphertext too short")
    out = bytearray(ciphertext)
    out[len(ciphertext) - 2 * crypto.BLOCK_SIZE] ^= 0x01
    return bytes(out)


def _tamper_padding(ciphertext: bytes) -> bytes:
    if len(ciphertext) < 2 * crypto.BLOCK_SIZE:
        raise ValueError("ciphertext too short")
    out = bytearray(ciphertext)
    # Flip the last byte of C_{n-1} to directly affect last-block padding.
    out[len(ciphertext) - crypto.BLOCK_SIZE - 1] ^= 0x01
    return bytes(out)


def _ensure_invalid_padding(client: protocol.Client, enc_key: bytes, base_ct: bytes) -> bytes:
    candidate = _tamper_padding(base_ct)
    if not _padding_valid_local(enc_key, candidate):
        ok, _ = client.check(candidate)
        if not ok:
            return candidate

    ok, _ = client.check(candidate)
    if not ok and not _padding_valid_local(enc_key, candidate):
        return candidate

    pad_pos = len(base_ct) - crypto.BLOCK_SIZE - 1
    for mask in range(2, 256):
        out = bytearray(base_ct)
        out[pad_pos] ^= mask
        candidate = bytes(out)
        if _padding_valid_local(enc_key, candidate):
            continue
        ok, _ = client.check(candidate)
        if not ok:
            return candidate
    raise RuntimeError("failed to produce invalid-padding sample")


def _padding_valid_local(enc_key: bytes, ciphertext: bytes) -> bool:
    try:
        padded = crypto.decrypt_cbc_raw(enc_key, ciphertext)
        _ = crypto.pkcs7_unpad(padded, crypto.BLOCK_SIZE)
        return True
    except Exception:
        return False


def _ensure_valid_padding_mac_fail(
    client: protocol.Client,
    enc_key: bytes,
    base_ct: bytes,
) -> bytes:
    if len(base_ct) < 2 * crypto.BLOCK_SIZE:
        raise ValueError("ciphertext too short")

    pad_pos = len(base_ct) - crypto.BLOCK_SIZE - 1
    for mask in range(1, 256):
        out = bytearray(base_ct)
        out[pad_pos] ^= mask
        candidate = bytes(out)
        if not _padding_valid_local(enc_key, candidate):
            continue
        ok, _ = client.check(candidate)
        if not ok:
            return candidate
    raise RuntimeError("failed to produce valid-padding MAC-fail sample")


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
            long_path_ct = _ensure_valid_padding_mac_fail(client, enc_key, ciphertext)
            short_path_ct = _ensure_invalid_padding(client, enc_key, ciphertext)

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
