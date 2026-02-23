from __future__ import annotations

import argparse
import base64
import time

from . import attacks, crypto, services


def main() -> None:
    parser = argparse.ArgumentParser(prog="padding-oracle", description="CBC padding-oracle project")
    sub = parser.add_subparsers(dest="command", required=True)

    p_task2 = sub.add_parser("task2", help="basic boolean padding-oracle attack")
    p_task2.add_argument("--message", default="CBC padding oracle demo for task 2.")

    args = parser.parse_args()

    if args.command == "task2":
        run_task2(args)
    else:
        raise ValueError(f"unknown command: {args.command}")


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


if __name__ == "__main__":
    main()
