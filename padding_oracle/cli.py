"""CLI entrypoints for task demos, benchmarks, and local service processes."""

from __future__ import annotations

import argparse
import time
from typing import Callable

from . import attacks, crypto, process, protocol, services, utils
from .console import CONSOLE

ATTACKER_PROGRESS_INTERVAL_SEC = 10.0


def _add_server_args(parser: argparse.ArgumentParser) -> None:
    """Attach common victim/server flags to a parser."""
    parser.add_argument("--addr", default="127.0.0.1:4000")
    parser.add_argument(
        "--enc-key",
        help="hex AES key (optional; random keys are generated when both keys are omitted)",
    )
    parser.add_argument(
        "--mac-key",
        help="hex HMAC key (optional; random keys are generated when both keys are omitted)",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="padding-oracle",
        description="CBC padding-oracle project command-line interface",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_server = sub.add_parser("server", help="run vulnerable MAC-then-encrypt victim/oracle")
    _add_server_args(p_server)

    p_victim = sub.add_parser("victim", help="alias of server for two-machine setups")
    _add_server_args(p_victim)

    p_boolean = sub.add_parser("boolean", help="basic boolean padding-oracle attack")
    p_boolean.add_argument("--message", default="CBC padding oracle demo for task 2.")

    p_timing = sub.add_parser("timing", help="self-contained local timing-oracle demo")
    p_timing.add_argument("--message")
    p_timing.add_argument("--message-kb", type=float)
    p_timing.add_argument("--target-block-index", type=int, help="1-based payload block index to recover")

    p_attacker = sub.add_parser("attacker", help="timing-oracle attacker against a remote/local victim")
    p_attacker.add_argument("--addr", required=True, help="victim/oracle address host:port")
    p_attacker.add_argument("--message")
    p_attacker.add_argument("--message-kb", type=float)
    p_attacker.add_argument("--target-block-index", type=int, help="1-based payload block index to recover")
    p_attacker.add_argument("--timeout", type=float, default=2.0, help="TCP connect timeout in seconds")
    p_attacker.add_argument(
        "--log-progress",
        action="store_true",
        help=f"log cumulative queries every {ATTACKER_PROGRESS_INTERVAL_SEC:.0f} seconds",
    )
    return parser


def main() -> None:
    """Parse arguments and dispatch to the selected subcommand."""
    args = build_parser().parse_args()
    handlers = {
        "server": run_server,
        "victim": run_server,
        "boolean": run_boolean,
        "timing": run_timing,
        "attacker": run_attacker,
    }
    try:
        handler = handlers[args.command]
    except KeyError as exc:
        raise ValueError(f"unknown command: {args.command}") from exc
    handler(args)


def run_server(args: argparse.Namespace) -> None:
    """Run the vulnerable MAC-then-encrypt receiver."""
    enc_key, mac_key = _resolve_server_keys(args.enc_key, args.mac_key)
    service = services.MacThenEncryptService(
        enc_key,
        mac_key,
    )
    CONSOLE.section("Victim / Oracle Server")
    CONSOLE.kv("addr", args.addr)
    CONSOLE.kv("enc_key", enc_key.hex())
    CONSOLE.kv("mac_key", mac_key.hex())
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
            (
                recovered,
                queries,
                elapsed_ms,
                target_block_index,
                target_name,
            ) = _recover_selected_block(
                client=client,
                message=msg,
                target_block_index=args.target_block_index,
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
            CONSOLE.kv("recovered_text", repr(_decode_recovered_text(recovered)))
            if not ok:
                CONSOLE.kv("expected_hex", expected.hex())
            CONSOLE.kv("success", CONSOLE.ok_label(ok))
    finally:
        process.stop_process(server_proc)


def run_attacker(args: argparse.Namespace) -> None:
    """Run timing attack against a manually started victim/oracle endpoint."""
    if args.timeout <= 0:
        raise ValueError("timeout must be > 0")

    msg, message_mode, message_kb = _resolve_message_bytes(args.message, args.message_kb)
    cfg = _timing_config()
    progress_callback = _build_queries_progress_callback(args.log_progress)

    CONSOLE.section("Timing Oracle Attacker")
    CONSOLE.kv("victim", args.addr)
    CONSOLE.kv("status", "starting execution...")

    process.wait_for_tcp(args.addr, timeout=max(0.1, args.timeout))
    with protocol.Client(args.addr, timeout=args.timeout) as client:
        (
            recovered,
            queries,
            elapsed_ms,
            target_block_index,
            target_name,
        ) = _recover_selected_block(
            client=client,
            message=msg,
            target_block_index=args.target_block_index,
            config=cfg,
            progress_callback=progress_callback,
        )

    CONSOLE.kv("message_mode", "literal" if message_mode == "literal" else f"random message_kb={message_kb}")
    CONSOLE.kv("message_bytes", len(msg))
    CONSOLE.kv("target", f"{target_name} (block_index={target_block_index})")
    CONSOLE.kv("queries", queries)
    CONSOLE.kv("elapsed_ms", f"{elapsed_ms:.2f}")
    CONSOLE.kv("recovered_hex", recovered.hex())
    CONSOLE.kv("recovered_text", repr(_decode_recovered_text(recovered)))
    expected_prefix = _expected_message_prefix_for_block(msg, target_block_index)
    verified = len(expected_prefix)
    CONSOLE.kv("verified_bytes", f"{verified}/{crypto.BLOCK_SIZE}")

    if verified == 0:
        CONSOLE.kv("success", CONSOLE.ok_label(False))
        CONSOLE.kv("note", "target block has no message bytes (MAC/padding only)")
        return

    ok = recovered[:verified] == expected_prefix
    if not ok:
        CONSOLE.kv("expected_message_prefix_hex", expected_prefix.hex())
    if verified < crypto.BLOCK_SIZE:
        CONSOLE.kv("note", "only message-prefix bytes are verifiable for this block")
    CONSOLE.kv("success", CONSOLE.ok_label(ok))


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


def _resolve_server_keys(
    enc_key_hex: str | None,
    mac_key_hex: str | None,
) -> tuple[bytes, bytes]:
    """Resolve explicit hex keys or generate both keys when omitted."""
    if enc_key_hex is None and mac_key_hex is None:
        return crypto.random_bytes(32), crypto.random_bytes(32)
    if enc_key_hex is None or mac_key_hex is None:
        raise ValueError("provide both --enc-key and --mac-key, or omit both")
    return utils.parse_hex_aes_key(enc_key_hex), utils.parse_hex_mac_key(mac_key_hex)


def _timing_config() -> attacks.TimingConfig:
    """Create internal timing attack configuration."""
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
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, int, float]:
    """Recover one block and return `(block, queries, elapsed_ms)`."""
    oracle = _make_timing_oracle(client)
    start = time.perf_counter_ns()
    recovered, queries = attacks.recover_ciphertext_block_timing(
        ciphertext,
        target_block_index,
        oracle,
        config,
        progress_callback=progress_callback,
    )
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    return recovered, queries, elapsed_ms


def _recover_selected_block(
    client: protocol.Client,
    message: bytes,
    target_block_index: int | None,
    config: attacks.TimingConfig,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[bytes, int, float, int, str]:
    """Encrypt message, choose target block, and recover that block."""
    ciphertext = client.encrypt(message)
    block_index, target_name = _resolve_target_block_index(
        ciphertext=ciphertext,
        msg_len=len(message),
        requested=target_block_index,
    )
    recovered, queries, elapsed_ms = _recover_target_block(
        client=client,
        ciphertext=ciphertext,
        target_block_index=block_index,
        config=config,
        progress_callback=progress_callback,
    )
    return recovered, queries, elapsed_ms, block_index, target_name


def _resolve_target_block_index(
    ciphertext: bytes,
    msg_len: int,
    requested: int | None,
) -> tuple[int, str]:
    """Resolve manual target index or default to fourth-last payload block."""
    if requested is None:
        if len(ciphertext) < 2 * crypto.BLOCK_SIZE or len(ciphertext) % crypto.BLOCK_SIZE != 0:
            raise ValueError("ciphertext must include IV and be a multiple of 16 bytes")
        _ = msg_len  # kept for call-site symmetry with previous selector variants
        num_blocks = len(ciphertext) // crypto.BLOCK_SIZE
        last_payload_block = num_blocks - 1
        if last_payload_block >= 4:
            return last_payload_block - 3, "fourth_last_payload_block"
        if last_payload_block <= 1:
            return 1, "only_payload_block"
        return 1, "first_payload_block_fallback"

    num_blocks = len(ciphertext) // crypto.BLOCK_SIZE
    if requested < 1 or requested >= num_blocks:
        raise ValueError(f"target block index {requested} out of range [1,{num_blocks - 1}]")
    return requested, "manual_payload_block"


def _decode_recovered_text(block: bytes) -> str:
    """Best-effort UTF-8 rendering for a recovered plaintext block."""
    return block.decode("utf-8", errors="replace")


def _expected_message_prefix_for_block(message: bytes, block_index: int) -> bytes:
    """Return known message bytes covered by the target payload block."""
    if block_index < 1:
        raise ValueError("block_index must be >= 1")
    start = (block_index - 1) * crypto.BLOCK_SIZE
    if start >= len(message):
        return b""
    end = min(start + crypto.BLOCK_SIZE, len(message))
    return message[start:end]


def _build_queries_progress_callback(
    enabled: bool,
) -> Callable[[int], None] | None:
    """Build a throttled progress logger for cumulative query count."""
    if not enabled:
        return None

    started = time.monotonic()
    last_emit = started

    def callback(queries: int) -> None:
        nonlocal last_emit
        now = time.monotonic()
        if now - last_emit < ATTACKER_PROGRESS_INTERVAL_SEC:
            return
        elapsed = now - started
        qps = queries / elapsed if elapsed > 0 else 0.0
        CONSOLE.kv("progress", f"queries={queries} elapsed_s={elapsed:.1f} qps={qps:.1f}")
        last_emit = now

    return callback


if __name__ == "__main__":
    main()
