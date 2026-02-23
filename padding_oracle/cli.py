from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import time

from . import attacks, crypto, process, protocol, services


def main() -> None:
    parser = argparse.ArgumentParser(prog="padding-oracle", description="CBC padding-oracle project (tasks 2, 3)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_server = sub.add_parser("server", help="run vulnerable MAC-then-encrypt receiver")
    p_server.add_argument("--addr", default="127.0.0.1:4000")
    p_server.add_argument("--enc-key", required=True, help="hex AES key")
    p_server.add_argument("--mac-key", required=True, help="hex HMAC key")
    p_server.add_argument("--mac-work", type=int, default=4000)

    p_task2 = sub.add_parser("task2", help="basic boolean padding-oracle attack")
    p_task2.add_argument("--message", default="CBC padding oracle demo for task 2.")

    p_task3 = sub.add_parser("task3", help="timing-oracle attack over localhost processes")
    p_task3.add_argument("--message", default="timing-block-demo")
    p_task3.add_argument("--block-index", type=int, default=1)
    p_task3.add_argument("--mac-work", type=int, default=4000)
    p_task3.add_argument("--initial-samples", type=int, default=1)
    p_task3.add_argument("--refine-samples", type=int, default=4)
    p_task3.add_argument("--top-k", type=int, default=6)

    args = parser.parse_args()

    if args.command == "server":
        run_server(args)
    elif args.command == "task2":
        run_task2(args)
    elif args.command == "task3":
        run_task3(args)
    else:
        raise ValueError(f"unknown command: {args.command}")


def run_server(args: argparse.Namespace) -> None:
    enc_key = _parse_hex_key(args.enc_key)
    mac_key = _parse_hex_key(args.mac_key)
    service = services.MacThenEncryptService(enc_key, mac_key, mac_work=args.mac_work)
    protocol.serve(args.addr, service)


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


if __name__ == "__main__":
    main()
