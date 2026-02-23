from __future__ import annotations

import argparse
import base64
import time

from . import attacks, crypto, protocol, services


def main() -> None:
    parser = argparse.ArgumentParser(prog="padding-oracle", description="CBC padding-oracle project")
    sub = parser.add_subparsers(dest="command", required=True)

    p_server = sub.add_parser("server", help="run vulnerable MAC-then-encrypt receiver")
    p_server.add_argument("--addr", default="127.0.0.1:4000")
    p_server.add_argument("--enc-key", required=True, help="hex AES key")
    p_server.add_argument("--mac-key", required=True, help="hex HMAC key")
    p_server.add_argument("--mac-work", type=int, default=4000)

    p_task2 = sub.add_parser("task2", help="basic boolean padding-oracle attack")
    p_task2.add_argument("--message", default="CBC padding oracle demo for task 2.")

    args = parser.parse_args()

    if args.command == "server":
        run_server(args)
    elif args.command == "task2":
        run_task2(args)
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


def _parse_hex_key(value: str) -> bytes:
    if not value:
        raise ValueError("missing key")
    out = bytes.fromhex(value)
    if len(out) not in (16, 24, 32):
        raise ValueError(f"invalid key length {len(out)}")
    return out


if __name__ == "__main__":
    main()
