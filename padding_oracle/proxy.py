from __future__ import annotations

import random
import socket
import time


def serve_proxy(listen_addr: str, target_addr: str, base_delay_s: float, jitter_s: float, seed: int) -> None:
    rng = random.Random(seed)
    listen_host, listen_port = _split_addr(listen_addr)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((listen_host, listen_port))
        server_sock.listen(5)

        while True:
            client_conn, _ = server_sock.accept()
            with client_conn:
                _handle_proxy_connection(client_conn, target_addr, base_delay_s, jitter_s, rng)


def _handle_proxy_connection(
    client_conn: socket.socket,
    target_addr: str,
    base_delay_s: float,
    jitter_s: float,
    rng: random.Random,
) -> None:
    target_host, target_port = _split_addr(target_addr)
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

                _delay(rng, base_delay_s, jitter_s)
                target_writer.write(line)
                target_writer.flush()

                response = target_reader.readline()
                if not response:
                    return

                _delay(rng, base_delay_s, jitter_s)
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


def _delay(rng: random.Random, base_delay_s: float, jitter_s: float) -> None:
    total = base_delay_s
    if jitter_s > 0:
        total += rng.uniform(-jitter_s, jitter_s)
        if total < 0:
            total = 0.0
    if total > 0:
        time.sleep(total)


def _split_addr(addr: str) -> tuple[str, int]:
    host, port_raw = addr.rsplit(":", 1)
    return host, int(port_raw)
