from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import time

from . import attacks, crypto, process, protocol, proxy, services


def main() -> None:
    parser = argparse.ArgumentParser(prog="padding-oracle", description="CBC padding-oracle project (tasks 2, 3, 4)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_server = sub.add_parser("server", help="run vulnerable MAC-then-encrypt receiver")
    p_server.add_argument("--addr", default="127.0.0.1:4000")
    p_server.add_argument("--enc-key", required=True, help="hex AES key")
    p_server.add_argument("--mac-key", required=True, help="hex HMAC key")
    p_server.add_argument("--mac-work", type=int, default=4000)

    p_proxy = sub.add_parser("proxy", help="run localhost delay/jitter proxy")
    p_proxy.add_argument("--listen", required=True)
    p_proxy.add_argument("--target", required=True)
    p_proxy.add_argument("--base-delay-ms", type=float, default=0.0)
    p_proxy.add_argument("--jitter-ms", type=float, default=0.0)
    p_proxy.add_argument("--seed", type=int, default=1)

    p_task2 = sub.add_parser("task2", help="basic boolean padding-oracle attack")
    p_task2.add_argument("--message", default="CBC padding oracle demo for task 2.")

    p_task3 = sub.add_parser("task3", help="timing-oracle attack over localhost processes")
    p_task3.add_argument("--message", default="timing-block-demo")
    p_task3.add_argument("--block-index", type=int, default=1)
    p_task3.add_argument("--mac-work", type=int, default=4000)
    p_task3.add_argument("--initial-samples", type=int, default=1)
    p_task3.add_argument("--refine-samples", type=int, default=4)
    p_task3.add_argument("--top-k", type=int, default=6)

    p_task4 = sub.add_parser("task4", help="benchmark timing attack under injected noise")
    p_task4.add_argument("--message", default="timing-block-demo")
    p_task4.add_argument("--block-index", type=int, default=1)
    p_task4.add_argument("--trials", type=int, default=3)
    p_task4.add_argument("--jitters-ms", default="0,0.05,0.1,0.2,0.5,1")
    p_task4.add_argument("--base-delay-ms", type=float, default=0.0)
    p_task4.add_argument("--mac-work", type=int, default=4000)
    p_task4.add_argument("--initial-samples", type=int, default=1)
    p_task4.add_argument("--refine-samples", type=int, default=5)
    p_task4.add_argument("--top-k", type=int, default=8)

    args = parser.parse_args()

    if args.command == "server":
        run_server(args)
    elif args.command == "proxy":
        run_proxy(args)
    elif args.command == "task2":
        run_task2(args)
    elif args.command == "task3":
        run_task3(args)
    elif args.command == "task4":
        run_task4(args)
    else:
        raise ValueError(f"unknown command: {args.command}")


def run_server(args: argparse.Namespace) -> None:
    enc_key = _parse_hex_key(args.enc_key)
    mac_key = _parse_hex_key(args.mac_key)
    service = services.MacThenEncryptService(enc_key, mac_key, mac_work=args.mac_work)
    protocol.serve(args.addr, service)


def run_proxy(args: argparse.Namespace) -> None:
    base_delay_s = _ms_to_seconds(args.base_delay_ms)
    jitter_s = _ms_to_seconds(args.jitter_ms)
    proxy.serve_proxy(args.listen, args.target, base_delay_s, jitter_s, args.seed)


def run_task2(args: argparse.Namespace) -> None:
    key = crypto.random_bytes(32)
    service = services.BasicOracleService(key)

    ciphertext = service.encrypt(args.message.encode("utf-8"))
    start = time.perf_counter_ns()
    recovered, queries = attacks.recover_plaintext_boolean(ciphertext, service.padding_oracle)
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

    print("task2: basic boolean padding-oracle attack")
    print(f"ciphertext (base64): {base64.b64encode(ciphertext).decode()}")
    print(f"queries: {queries}")
    print(f"elapsed_ms: {elapsed_ms:.2f}")
    print(f"recovered: {recovered.decode(errors='replace')!r}")
    print(f"success: {recovered == args.message.encode('utf-8')}")


def run_task3(args: argparse.Namespace) -> None:
    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)
    msg = args.message.encode("utf-8")

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
            "--mac-work",
            str(args.mac_work),
        ]
    )

    try:
        process.wait_for_tcp(server_addr, timeout=3.0)
        with protocol.Client(server_addr, timeout=2.0) as client:
            ciphertext = client.encrypt(msg)

            def oracle(candidate: bytes) -> int:
                _, delta_ns = client.check(candidate)
                return delta_ns

            cfg = attacks.TimingConfig(
                initial_samples=args.initial_samples,
                refine_samples=args.refine_samples,
                top_candidates=args.top_k,
            )

            start = time.perf_counter_ns()
            recovered, queries = attacks.recover_ciphertext_block_timing(
                ciphertext, args.block_index, oracle, cfg
            )
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

            expected = _expected_payload_block(msg, mac_key, args.block_index)

            print("task3: timing oracle attack over localhost process boundary")
            print(f"server: {server_addr}")
            print(f"target_block: {args.block_index}")
            print(f"queries: {queries}")
            print(f"elapsed_ms: {elapsed_ms:.2f}")
            print(f"recovered_hex: {recovered.hex()}")
            print(f"expected_hex:  {expected.hex()}")
            print(f"recovered_ascii: {recovered.decode(errors='replace')!r}")
            print(f"success: {recovered == expected}")
    finally:
        process.stop_process(server_proc)


def run_task4(args: argparse.Namespace) -> None:
    if args.trials < 1:
        raise ValueError("trials must be >= 1")

    jitters_ms = _parse_csv_floats(args.jitters_ms)
    _ = _ms_to_seconds(args.base_delay_ms)
    for jitter_ms in jitters_ms:
        _ = _ms_to_seconds(jitter_ms)

    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)
    msg = args.message.encode("utf-8")

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
            "--mac-work",
            str(args.mac_work),
        ]
    )

    try:
        process.wait_for_tcp(server_addr, timeout=3.0)
        expected = _expected_payload_block(msg, mac_key, args.block_index)

        cfg = attacks.TimingConfig(
            initial_samples=args.initial_samples,
            refine_samples=args.refine_samples,
            top_candidates=args.top_k,
        )

        print("task4: timing-attack robustness under injected localhost noise")
        print(f"server={server_addr} base_delay_ms={args.base_delay_ms:.6f} trials={args.trials}")
        print("jitter_ms success_rate avg_queries avg_elapsed_ms completed_trials error_trials")

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
                    str(1337 + i),
                ]
            )

            success = 0
            total_queries = 0
            total_elapsed_ms = 0.0
            completed_trials = 0
            error_trials = 0
            last_error: Exception | None = None

            try:
                try:
                    process.wait_for_tcp(proxy_addr, timeout=3.0)
                except Exception as exc:
                    error_trials = args.trials
                    last_error = exc
                else:
                    for _ in range(args.trials):
                        try:
                            with protocol.Client(proxy_addr, timeout=2.0) as client:
                                ciphertext = client.encrypt(msg)

                                def oracle(candidate: bytes) -> int:
                                    _, delta_ns = client.check(candidate)
                                    return delta_ns

                                start = time.perf_counter_ns()
                                recovered, queries = attacks.recover_ciphertext_block_timing(
                                    ciphertext,
                                    args.block_index,
                                    oracle,
                                    cfg,
                                )
                                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                                total_elapsed_ms += elapsed_ms
                                total_queries += queries
                                completed_trials += 1
                                if recovered == expected:
                                    success += 1
                        except Exception as exc:
                            error_trials += 1
                            last_error = exc
            finally:
                process.stop_process(proxy_proc)

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
            if error_trials > 0:
                print(
                    f"note: jitter_ms={jitter_ms:.6f} had {error_trials}/{args.trials} "
                    f"trial errors (last_error={type(last_error).__name__ if last_error else 'unknown'})"
                )
    finally:
        process.stop_process(server_proc)


def _expected_payload_block(msg: bytes, mac_key: bytes, block_index: int) -> bytes:
    tag = hmac.new(mac_key, msg, hashlib.sha256).digest()
    payload = crypto.pkcs7_pad(msg + tag, crypto.BLOCK_SIZE)
    blocks = len(payload) // crypto.BLOCK_SIZE
    if block_index < 1 or block_index > blocks:
        raise ValueError(f"block index {block_index} out of range [1,{blocks}]")
    start = (block_index - 1) * crypto.BLOCK_SIZE
    return payload[start : start + crypto.BLOCK_SIZE]


def _parse_hex_key(value: str) -> bytes:
    if not value:
        raise ValueError("missing key")
    out = bytes.fromhex(value)
    if len(out) not in (16, 24, 32):
        raise ValueError(f"invalid key length {len(out)}")
    return out


def _parse_csv_floats(raw: str) -> list[float]:
    values: list[float] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        value = float(part)
        if value < 0:
            raise ValueError("negative values are not allowed")
        values.append(value)
    if not values:
        raise ValueError("no values provided")
    return values


def _ms_to_seconds(value: float) -> float:
    if value < 0:
        raise ValueError("must be non-negative")
    return value / 1000.0


if __name__ == "__main__":
    main()
