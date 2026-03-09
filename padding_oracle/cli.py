"""CLI entrypoints for task demos, benchmarks, and local service processes."""

from __future__ import annotations

import argparse
import base64
import time
from dataclasses import dataclass
from typing import Callable

from . import attacks, crypto, process, protocol, proxy, services, utils


@dataclass
class TrialAggregate:
    """Running aggregate for task4 trials at one jitter value."""

    success: int = 0
    total_queries: int = 0
    total_elapsed_ms: float = 0.0
    completed_trials: int = 0
    error_trials: int = 0
    last_error: Exception | None = None


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="padding-oracle",
        description="CBC padding-oracle project (tasks 2, 3, 4)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_server = sub.add_parser("server", help="run vulnerable MAC-then-encrypt receiver")
    p_server.add_argument("--addr", default="127.0.0.1:4000")
    p_server.add_argument("--enc-key", required=True, help="hex AES key")
    p_server.add_argument("--mac-key", required=True, help="hex HMAC key")

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
    p_task3.add_argument("--refine-samples", type=int, default=12)
    p_task3.add_argument("--top-k", type=int, default=12)

    p_task4 = sub.add_parser("task4", help="benchmark timing attack under injected noise")
    p_task4.add_argument("--message")
    p_task4.add_argument("--message-kb", type=float)
    p_task4.add_argument("--trials", type=int, default=3)
    p_task4.add_argument("--jitters-ms", default="0,0.005,0.01,0.015")
    p_task4.add_argument("--initial-samples", type=int, default=4)
    p_task4.add_argument("--refine-samples", type=int, default=12)
    p_task4.add_argument("--top-k", type=int, default=12)
    return parser


def main() -> None:
    """Parse arguments and dispatch to the selected subcommand."""
    args = build_parser().parse_args()
    handlers = {
        "server": run_server,
        "proxy": run_proxy,
        "task2": run_task2,
        "task3": run_task3,
        "task4": run_task4,
    }
    try:
        handler = handlers[args.command]
    except KeyError as exc:
        raise ValueError(f"unknown command: {args.command}") from exc
    handler(args)


def run_server(args: argparse.Namespace) -> None:
    """Run the vulnerable MAC-then-encrypt receiver."""
    enc_key = utils.parse_hex_aes_key(args.enc_key)
    mac_key = utils.parse_hex_mac_key(args.mac_key)
    service = services.MacThenEncryptService(
        enc_key,
        mac_key,
    )
    protocol.serve(args.addr, service)


def run_proxy(args: argparse.Namespace) -> None:
    """Run a localhost jitter proxy used in timing experiments."""
    jitter_s = utils.ms_to_seconds(args.jitter_ms)
    proxy.serve_proxy(args.listen, args.target, jitter_s)


def run_task2(args: argparse.Namespace) -> None:
    """Run the classic boolean padding-oracle plaintext recovery demo."""
    key = crypto.random_bytes(32)
    service = services.BasicOracleService(key)

    message = args.message.encode("utf-8")
    ciphertext = service.encrypt(message)
    start = time.perf_counter_ns()
    recovered, queries = attacks.recover_plaintext_boolean(ciphertext, service.padding_oracle)
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

    print("task2: basic boolean padding-oracle attack")
    print(f"ciphertext (base64): {base64.b64encode(ciphertext).decode()}")
    print(f"queries: {queries}")
    print(f"elapsed_ms: {elapsed_ms:.2f}")
    print(f"recovered: {recovered.decode(errors='replace')!r}")
    print(f"success: {recovered == message}")


def run_task3(args: argparse.Namespace) -> None:
    """Recover one selected payload block using timing information."""
    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)
    msg, message_mode, message_kb = _resolve_message_bytes(args.message, args.message_kb)
    cfg = _timing_config_from_args(args)

    server_addr = process.free_local_addr()
    server_proc = _start_server(server_addr, enc_key, mac_key, args)

    try:
        process.wait_for_tcp(server_addr, timeout=3.0)
        with protocol.Client(server_addr, timeout=2.0) as client:
            ciphertext = client.encrypt(msg)
            target_block_index, target_name = utils.choose_single_block_target(
                ciphertext,
                msg_len=len(msg),
            )

            recovered, queries, elapsed_ms = _recover_target_block(
                client=client,
                ciphertext=ciphertext,
                target_block_index=target_block_index,
                config=cfg,
            )

            expected = utils.expected_payload_block(
                msg,
                mac_key,
                target_block_index,
            )

            print("task3: timing oracle attack over localhost process boundary")
            print(f"server: {server_addr}")
            if message_mode == "literal":
                print("message_mode: literal")
            else:
                print(f"message_mode: random message_kb={message_kb}")
            print(f"message_bytes: {len(msg)}")
            print(f"target: {target_name} (block_index={target_block_index})")
            print(f"queries: {queries}")
            print(f"elapsed_ms: {elapsed_ms:.2f}")
            print(f"recovered_hex: {recovered.hex()}")
            print(f"expected_hex:  {expected.hex()}")
            print(f"success: {recovered == expected}")
    finally:
        process.stop_process(server_proc)


def run_task4(args: argparse.Namespace) -> None:
    """Benchmark timing attack robustness under different proxy jitter levels."""
    if args.trials < 1:
        raise ValueError("trials must be >= 1")

    jitters_ms = _parse_jitter_values(args.jitters_ms)

    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)
    base_message, message_mode, message_kb = _resolve_message_bytes(args.message, args.message_kb)
    cfg = _timing_config_from_args(args)

    server_addr = process.free_local_addr()
    server_proc = _start_server(server_addr, enc_key, mac_key, args)

    try:
        process.wait_for_tcp(server_addr, timeout=3.0)

        print("task4: timing-attack robustness under injected localhost noise")
        print(f"server={server_addr} trials={args.trials}")
        if message_mode == "literal":
            print(f"message_mode=literal message_bytes={len(base_message)}")
        else:
            print(f"message_mode=random message_kb={message_kb}")
        print("mode=single_block target=auto(last_or_second_last_if_full_padding)")
        print(
            "jitter_ms success_rate avg_queries avg_elapsed_ms "
            "completed_trials error_trials successes total_trials"
        )

        for jitter_ms in jitters_ms:
            aggregate = _run_jitter_trials(
                jitter_ms=jitter_ms,
                trials=args.trials,
                base_message=base_message,
                server_addr=server_addr,
                mac_key=mac_key,
                args=args,
                cfg=cfg,
            )

            success_rate = aggregate.success / args.trials
            if aggregate.completed_trials > 0:
                avg_queries = aggregate.total_queries / aggregate.completed_trials
                avg_elapsed_ms = aggregate.total_elapsed_ms / aggregate.completed_trials
            else:
                avg_queries = float("nan")
                avg_elapsed_ms = float("nan")
            print(
                f"{jitter_ms:.6f} {success_rate:.5f} {avg_queries:.1f} {avg_elapsed_ms:.2f} "
                f"{aggregate.completed_trials} {aggregate.error_trials} {aggregate.success} {args.trials}"
            )
            if aggregate.error_trials > 0:
                print(
                    f"note: jitter_ms={jitter_ms:.6f} had {aggregate.error_trials}/{args.trials} "
                    f"trial errors (last_error="
                    f"{type(aggregate.last_error).__name__ if aggregate.last_error else 'unknown'})"
                )
    finally:
        process.stop_process(server_proc)


def _start_server(
    server_addr: str,
    enc_key: bytes,
    mac_key: bytes,
    args: argparse.Namespace,
):
    """Spawn the task server process with arguments from the current command."""
    return process.start_self_process(
        utils.server_command_args(
            server_addr,
            enc_key,
            mac_key,
        )
    )


def _resolve_message_bytes(
    message: str | None,
    message_kb: float | None,
) -> tuple[bytes, str, float | None]:
    """Resolve message inputs into bytes and a `(mode, message_kb)` descriptor."""
    if message is not None:
        if message_kb is not None:
            print("warning: --message-kb is ignored because --message was provided")
        return message.encode("utf-8"), "literal", None

    selected_kb = 1.0 if message_kb is None else message_kb
    # Validation happens inside random_message_from_kb via kb_to_bytes.
    return utils.random_message_from_kb(selected_kb), "random", selected_kb


def _parse_jitter_values(raw_jitters: str) -> list[float]:
    """Parse and validate jitter values supplied in milliseconds."""
    jitters_ms = utils.parse_csv_floats(raw_jitters)
    for jitter_ms in jitters_ms:
        _ = utils.ms_to_seconds(jitter_ms)
    return jitters_ms


def _timing_config_from_args(args: argparse.Namespace) -> attacks.TimingConfig:
    """Create timing attack config from CLI namespace values."""
    return attacks.TimingConfig(
        initial_samples=args.initial_samples,
        refine_samples=args.refine_samples,
        top_candidates=args.top_k,
    )


def _make_timing_oracle(client: protocol.Client) -> Callable[[bytes], int]:
    """Wrap protocol client check into attack-compatible oracle signature."""

    def oracle(candidate: bytes) -> int:
        _, delta_ns = client.check(candidate)
        return delta_ns

    return oracle


def _recover_target_block(
    client: protocol.Client,
    ciphertext: bytes,
    target_block_index: int,
    config: attacks.TimingConfig,
) -> tuple[bytes, int, float]:
    """Recover one block and return `(block, queries, elapsed_ms)`."""
    oracle = _make_timing_oracle(client)
    start = time.perf_counter_ns()
    recovered, queries = attacks.recover_ciphertext_block_timing(
        ciphertext,
        target_block_index,
        oracle,
        config,
    )
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    return recovered, queries, elapsed_ms


def _run_single_trial(
    client: protocol.Client,
    message: bytes,
    mac_key: bytes,
    args: argparse.Namespace,
    cfg: attacks.TimingConfig,
) -> tuple[bool, int, float]:
    """Run one task4 trial and return `(success, queries, elapsed_ms)`."""
    ciphertext = client.encrypt(message)
    target_block_index, _ = utils.choose_single_block_target(
        ciphertext,
        msg_len=len(message),
    )
    expected = utils.expected_payload_block(
        message,
        mac_key,
        target_block_index,
    )
    recovered, queries, elapsed_ms = _recover_target_block(
        client=client,
        ciphertext=ciphertext,
        target_block_index=target_block_index,
        config=cfg,
    )
    return recovered == expected, queries, elapsed_ms


def _run_jitter_trials(
    jitter_ms: float,
    trials: int,
    base_message: bytes,
    server_addr: str,
    mac_key: bytes,
    args: argparse.Namespace,
    cfg: attacks.TimingConfig,
) -> TrialAggregate:
    """Run all trials for one jitter value and return aggregate metrics."""
    aggregate = TrialAggregate()
    # Start one proxy per jitter row so each row has isolated noise settings.
    proxy_addr = process.free_local_addr()
    proxy_proc = process.start_self_process(
        utils.proxy_command_args(
            listen_addr=proxy_addr,
            target_addr=server_addr,
            jitter_ms=jitter_ms,
        )
    )

    try:
        try:
            process.wait_for_tcp(proxy_addr, timeout=3.0)
        except Exception as exc:
            # If the proxy never came up, mark every trial as an error.
            aggregate.error_trials = trials
            aggregate.last_error = exc
            return aggregate

        for _ in range(trials):
            try:
                with protocol.Client(proxy_addr, timeout=2.0) as client:
                    success, queries, elapsed_ms = _run_single_trial(
                        client=client,
                        message=base_message,
                        mac_key=mac_key,
                        args=args,
                        cfg=cfg,
                    )
            except Exception as exc:
                aggregate.error_trials += 1
                aggregate.last_error = exc
                continue

            # Completed trials contribute to averages; failed trials are counted separately.
            aggregate.completed_trials += 1
            aggregate.total_queries += queries
            aggregate.total_elapsed_ms += elapsed_ms
            if success:
                aggregate.success += 1
    finally:
        process.stop_process(proxy_proc)

    return aggregate


if __name__ == "__main__":
    main()
