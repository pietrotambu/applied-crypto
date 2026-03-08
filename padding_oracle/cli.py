from __future__ import annotations

import argparse
import base64
import time

from . import attacks, crypto, process, protocol, proxy, services, utils


def main() -> None:
    parser = argparse.ArgumentParser(prog="padding-oracle", description="CBC padding-oracle project (tasks 2, 3, 4)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_server = sub.add_parser("server", help="run vulnerable MAC-then-encrypt receiver")
    p_server.add_argument("--addr", default="127.0.0.1:4000")
    p_server.add_argument("--enc-key", required=True, help="hex AES key")
    p_server.add_argument("--mac-key", required=True, help="hex HMAC key")
    p_server.add_argument("--timing-work-factor", type=int, default=0)

    p_proxy = sub.add_parser("proxy", help="run localhost delay/jitter proxy")
    p_proxy.add_argument("--listen", required=True)
    p_proxy.add_argument("--target", required=True)
    p_proxy.add_argument("--jitter-ms", type=float, default=0.0)

    p_task2 = sub.add_parser("task2", help="basic boolean padding-oracle attack")
    p_task2.add_argument("--message", default="CBC padding oracle demo for task 2.")

    p_task3 = sub.add_parser("task3", help="timing-oracle attack over localhost processes")
    p_task3.add_argument("--message")
    p_task3.add_argument("--message-kb", type=float)
    p_task3.add_argument("--initial-samples", type=int, default=4)
    p_task3.add_argument("--refine-samples", type=int, default=8)
    p_task3.add_argument("--top-k", type=int, default=8)
    p_task3.add_argument("--timing-work-factor", type=int, default=0)

    p_task4 = sub.add_parser("task4", help="benchmark timing attack under injected noise")
    p_task4.add_argument("--message")
    p_task4.add_argument("--message-kb", type=float)
    p_task4.add_argument("--trials", type=int, default=3)
    p_task4.add_argument("--jitters-ms", default="0,0.005,0.01,0.015")
    p_task4.add_argument("--initial-samples", type=int, default=4)
    p_task4.add_argument("--refine-samples", type=int, default=8)
    p_task4.add_argument("--top-k", type=int, default=8)
    p_task4.add_argument("--timing-work-factor", type=int, default=0)

    args = parser.parse_args()

    if args.command == "server": run_server(args)
    elif args.command == "proxy": run_proxy(args)
    elif args.command == "task2": run_task2(args)
    elif args.command == "task3": run_task3(args)
    elif args.command == "task4": run_task4(args)
    else: raise ValueError(f"unknown command: {args.command}")


def run_server(args: argparse.Namespace) -> None:
    enc_key = utils.parse_hex_aes_key(args.enc_key)
    mac_key = utils.parse_hex_mac_key(args.mac_key)
    service = services.MacThenEncryptService(
        enc_key,
        mac_key,
        timing_work_factor=args.timing_work_factor,
    )
    protocol.serve(args.addr, service)


def run_proxy(args: argparse.Namespace) -> None:
    jitter_s = utils.ms_to_seconds(args.jitter_ms)
    proxy.serve_proxy(args.listen, args.target, jitter_s)


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
    if args.message is not None:
        if args.message_kb is not None:
            print("warning: --message-kb is ignored because --message was provided")
        msg = args.message.encode("utf-8")
        message_mode = "literal"
        message_kb = None
    else:
        message_kb = 1.0 if args.message_kb is None else args.message_kb
        msg = utils.random_message_from_kb(message_kb)
        message_mode = "random"

    server_addr = process.free_local_addr()
    server_proc = process.start_self_process(
        utils.server_command_args(
            server_addr,
            enc_key,
            mac_key,
            timing_work_factor=args.timing_work_factor,
        )
    )

    try:
        process.wait_for_tcp(server_addr, timeout=3.0)
        with protocol.Client(server_addr, timeout=2.0) as client:
            ciphertext = client.encrypt(msg)
            num_blocks = len(ciphertext) // crypto.BLOCK_SIZE
            last_block_index = num_blocks - 1

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
                ciphertext,
                last_block_index,
                oracle,
                cfg,
            )
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

            expected = utils.expected_payload_block(msg, mac_key, last_block_index)

            print("task3: timing oracle attack over localhost process boundary")
            print(f"server: {server_addr}")
            print(f"timing_work_factor: {args.timing_work_factor}")
            if message_mode == "literal":
                print("message_mode: literal")
            else:
                print(f"message_mode: random message_kb={message_kb}")
            print(f"message_bytes: {len(msg)}")
            print(f"target: last_payload_block (block_index={last_block_index})")
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

    jitters_ms = utils.parse_csv_floats(args.jitters_ms)
    for jitter_ms in jitters_ms:
        _ = utils.ms_to_seconds(jitter_ms)

    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)

    fixed_message: bytes | None = None
    message_kb: float | None = None
    if args.message is not None:
        if args.message_kb is not None:
            print("warning: --message-kb is ignored because --message was provided")
        fixed_message = args.message.encode("utf-8")
    else:
        message_kb = 1.0 if args.message_kb is None else args.message_kb
        _ = utils.kb_to_bytes(message_kb)

    server_addr = process.free_local_addr()
    server_proc = process.start_self_process(
        utils.server_command_args(
            server_addr,
            enc_key,
            mac_key,
            timing_work_factor=args.timing_work_factor,
        )
    )

    try:
        process.wait_for_tcp(server_addr, timeout=3.0)
        cfg = attacks.TimingConfig(
            initial_samples=args.initial_samples,
            refine_samples=args.refine_samples,
            top_candidates=args.top_k,
        )

        print("task4: timing-attack robustness under injected localhost noise")
        print(
            f"server={server_addr} trials={args.trials} "
            f"timing_work_factor={args.timing_work_factor}"
        )
        if fixed_message is not None:
            print(f"message_mode=literal message_bytes={len(fixed_message)}")
        else:
            print(f"message_mode=random message_kb={message_kb}")
        print("mode=single_block target=last_payload_block")
        print(
            "jitter_ms success_rate avg_queries avg_elapsed_ms "
            "completed_trials error_trials successes total_trials"
        )

        for jitter_ms in jitters_ms:
            proxy_addr = process.free_local_addr()
            proxy_proc = process.start_self_process(
                utils.proxy_command_args(
                    listen_addr=proxy_addr,
                    target_addr=server_addr,
                    jitter_ms=jitter_ms,
                )
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
                                if fixed_message is not None:
                                    msg = fixed_message
                                else:
                                    msg = utils.random_message_from_kb(message_kb)
                                ciphertext = client.encrypt(msg)
                                num_blocks = len(ciphertext) // crypto.BLOCK_SIZE
                                last_block_index = num_blocks - 1
                                expected = utils.expected_payload_block(msg, mac_key, last_block_index)

                                def oracle(candidate: bytes) -> int:
                                    _, delta_ns = client.check(candidate)
                                    return delta_ns

                                start = time.perf_counter_ns()
                                recovered, queries = attacks.recover_ciphertext_block_timing(
                                    ciphertext,
                                    last_block_index,
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
                f"{jitter_ms:.6f} {success_rate:.5f} {avg_queries:.1f} {avg_elapsed_ms:.2f} "
                f"{completed_trials} {error_trials} {success} {args.trials}"
            )
            if error_trials > 0:
                print(
                    f"note: jitter_ms={jitter_ms:.6f} had {error_trials}/{args.trials} "
                    f"trial errors (last_error={type(last_error).__name__ if last_error else 'unknown'})"
                )
    finally:
        process.stop_process(server_proc)


if __name__ == "__main__":
    main()
