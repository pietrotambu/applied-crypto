"""CLI entrypoints for task demos, benchmarks, and local service processes."""

from __future__ import annotations

import argparse
import time
from typing import Callable

from . import attacks, crypto, process, protocol, services, utils
from .console import CONSOLE


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="padding-oracle",
        description="CBC padding-oracle project command-line interface",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_server = sub.add_parser("server", help="run vulnerable MAC-then-encrypt receiver")
    p_server.add_argument("--addr", default="127.0.0.1:4000")
    p_server.add_argument("--enc-key", required=True, help="hex AES key")
    p_server.add_argument("--mac-key", required=True, help="hex HMAC key")

    p_boolean = sub.add_parser("boolean", help="basic boolean padding-oracle attack")
    p_boolean.add_argument("--message", default="CBC padding oracle demo for task 2.")

    p_timing = sub.add_parser("timing", help="timing-oracle attack over localhost processes")
    p_timing.add_argument("--message")
    p_timing.add_argument("--message-kb", type=float)
    return parser


def main() -> None:
    """Parse arguments and dispatch to the selected subcommand."""
    args = build_parser().parse_args()
    handlers = {
        "server": run_server,
        "boolean": run_boolean,
        "timing": run_timing,
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


def run_boolean(args: argparse.Namespace) -> None:
    """Run the classic boolean padding-oracle plaintext recovery demo."""
    key = crypto.random_bytes(32)
    service = services.BasicOracleService(key)

    message = args.message.encode("utf-8")
    ciphertext = service.encrypt(message)
    start = time.perf_counter_ns()
    recovered, queries = attacks.recover_plaintext_boolean(ciphertext, service.padding_oracle)
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

    ok = recovered == message
    CONSOLE.section("Task 2 - Boolean Padding Oracle")
    CONSOLE.kv("queries", queries)
    CONSOLE.kv("elapsed_ms", f"{elapsed_ms:.2f}")
    CONSOLE.kv("recovered", repr(recovered.decode(errors="replace")))
    CONSOLE.kv("success", CONSOLE.ok_label(ok))


def run_timing(args: argparse.Namespace) -> None:
    """Recover one selected payload block using timing information."""
    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)
    msg, message_mode, message_kb = _resolve_message_bytes(args.message, args.message_kb)
    cfg = _timing_config()

    server_addr = process.free_local_addr()
    server_proc = _start_server(server_addr, enc_key, mac_key)
    CONSOLE.section("Task 3 - Timing Oracle Attack")
    CONSOLE.kv("status", "starting execution...")

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

            ok = recovered == expected
            CONSOLE.kv("server", server_addr)
            if message_mode == "literal":
                CONSOLE.kv("message_mode", "literal")
            else:
                CONSOLE.kv("message_mode", f"random message_kb={message_kb}")
            CONSOLE.kv("message_bytes", len(msg))
            CONSOLE.kv("target", f"{target_name} (block_index={target_block_index})")
            CONSOLE.kv("queries", queries)
            CONSOLE.kv("elapsed_ms", f"{elapsed_ms:.2f}")
            CONSOLE.kv("recovered_hex", recovered.hex())
            if not ok:
                CONSOLE.kv("expected_hex", expected.hex())
            CONSOLE.kv("success", CONSOLE.ok_label(ok))
    finally:
        process.stop_process(server_proc)


def _start_server(
    server_addr: str,
    enc_key: bytes,
    mac_key: bytes,
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
            CONSOLE.warn("--message-kb is ignored because --message was provided")
        return message.encode("utf-8"), "literal", None

    selected_kb = 1.0 if message_kb is None else message_kb
    # Validation happens inside random_message_from_kb via kb_to_bytes.
    return utils.random_message_from_kb(selected_kb), "random", selected_kb


def _timing_config() -> attacks.TimingConfig:
    """Create internal timing attack configuration (auto mode)."""
    return attacks.TimingConfig(
        initial_samples=2,
        refine_samples=2,
        top_candidates=8,
        confidence_z=2.5,
        min_compare_samples=10,
        max_queries_per_byte=100_000,
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


if __name__ == "__main__":
    main()
