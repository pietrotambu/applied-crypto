"""TCP proxy with optional per-direction jitter injection."""

from __future__ import annotations

import random
import socket
import time

from . import utils

_SPIN_GUARD_NS = 50_000
_SLEEP_COARSE_NS = 2_000_000  # 2 ms


def serve_proxy(listen_addr: str, target_addr: str, jitter_s: float) -> None:
    """Run a single-threaded proxy from `listen_addr` to `target_addr`."""
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
    """Forward one client connection line-by-line with optional jitter."""
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
    """Sleep a random delay in `[0, jitter_s]` with half-normal density."""
    if jitter_s <= 0:
        return

    sigma = jitter_s / 3.0
    if sigma <= 0:
        return
    while True:
        total = abs(rng.gauss(0.0, sigma))
        if total <= jitter_s:
            break
    _sleep_precise(total)


def _sleep_precise(total_s: float) -> None:
    """Sleep with coarse waiting followed by short spin for better precision."""
    total_ns = int(total_s * 1_000_000_000)
    if total_ns <= 0:
        return

    deadline_ns = time.perf_counter_ns() + total_ns

    if total_ns >= _SLEEP_COARSE_NS:
        while True:
            now_ns = time.perf_counter_ns()
            remaining_ns = deadline_ns - now_ns
            if remaining_ns <= _SPIN_GUARD_NS:
                break
            time.sleep((remaining_ns - _SPIN_GUARD_NS) / 1_000_000_000.0)

    while time.perf_counter_ns() < deadline_ns:
        pass
