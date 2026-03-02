from __future__ import annotations

import random
import socket
import time

from . import utils

_SPIN_GUARD_NS = 50_000
_SLEEP_COARSE_NS = 200_000


def serve_proxy(listen_addr: str, target_addr: str, jitter_s: float) -> None:
    rng = random.Random()
    listen_host, listen_port = utils.split_addr(listen_addr)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((listen_host, listen_port))
        server_sock.listen(5)

        while True:
            client_conn, _ = server_sock.accept()
            with client_conn:
                _handle_proxy_connection(client_conn, target_addr, jitter_s, rng)


def _handle_proxy_connection(
    client_conn: socket.socket,
    target_addr: str,
    jitter_s: float,
    rng: random.Random,
) -> None:
    target_host, target_port = utils.split_addr(target_addr)
    with socket.create_connection((target_host, target_port), timeout=2.0) as target_conn:
        client_reader = client_conn.makefile("rb")
        client_writer = client_conn.makefile("wb")
        target_reader = target_conn.makefile("rb")
        target_writer = target_conn.makefile("wb")
        try:
            while True:
                line = client_reader.readline()
                if not line:
                    return

                _delay(rng, jitter_s)
                target_writer.write(line)
                target_writer.flush()

                response = target_reader.readline()
                if not response:
                    return

                _delay(rng, jitter_s)
                client_writer.write(response)
                client_writer.flush()
        finally:
            try:
                client_writer.close()
            except Exception:
                pass
            try:
                client_reader.close()
            except Exception:
                pass
            try:
                target_writer.close()
            except Exception:
                pass
            try:
                target_reader.close()
            except Exception:
                pass


def _delay(rng: random.Random, jitter_s: float) -> None:
    total = 0.0
    if jitter_s > 0:
        total += rng.uniform(-jitter_s, jitter_s)
        if total < 0:
            total = 0.0
    if total > 0:
        _sleep_precise(total)


def _sleep_precise(total_s: float) -> None:
    # Use busy-wait for tiny delays so sub-microsecond jitter is not rounded away
    # by scheduler-backed sleep resolution. For larger delays, sleep most of the
    # interval and finish with a short spin.
    total_ns = int(total_s * 1_000_000_000)
    if total_ns <= 0:
        return

    start_ns = time.perf_counter_ns()
    deadline_ns = start_ns + total_ns

    if total_ns >= _SLEEP_COARSE_NS:
        sleep_ns = total_ns - _SPIN_GUARD_NS
        if sleep_ns > 0:
            time.sleep(sleep_ns / 1_000_000_000.0)

    while time.perf_counter_ns() < deadline_ns:
        pass
