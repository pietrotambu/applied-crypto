"""Simple line-based TCP protocol for encrypt/check requests."""

from __future__ import annotations

import base64
import socket
import time
from typing import Protocol

from . import utils


class Service(Protocol):
    """Protocol contract expected by the TCP server."""

    def encrypt(self, plaintext: bytes) -> bytes: ...

    def check(self, ciphertext: bytes) -> bool: ...


def serve(addr: str, service: Service) -> None:
    """Serve one connection at a time on `addr`."""
    host, port = utils.split_addr(addr)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        while True:
            conn, _ = sock.accept()
            with conn:
                _handle_connection(conn, service)


def _handle_connection(conn: socket.socket, service: Service) -> None:
    """Handle requests on one TCP connection until EOF."""
    reader = conn.makefile("rb")
    writer = conn.makefile("wb")
    try:
        while True:
            line = reader.readline()
            if not line: return
            line = line.strip()
            if not line: continue

            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                writer.write(b"ERR\n")
                writer.flush()
                continue

            cmd, encoded = parts
            cmd_upper = cmd.upper()
            try:
                payload = base64.b64decode(encoded, validate=True)
            except Exception:
                writer.write(b"ERR\n")
                writer.flush()
                continue

            if cmd_upper == b"ENCRYPT":
                try:
                    ct = service.encrypt(payload)
                    writer.write(b"CT " + base64.b64encode(ct) + b"\n")
                except Exception:
                    writer.write(b"ERR\n")
                writer.flush()
                continue

            if cmd_upper == b"CHECK":
                try:
                    ok = service.check(payload)
                except Exception:
                    ok = False
                writer.write(b"OK\n" if ok else b"ERR\n")
                writer.flush()
                continue

            writer.write(b"ERR\n")
            writer.flush()
    finally:
        try:
            writer.close()
        finally:
            reader.close()


class Client:
    """Convenience client for the line-based protocol."""

    def __init__(self, addr: str, timeout: float = 2.0):
        host, port = utils.split_addr(addr)
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._reader = self._sock.makefile("rb")
        self._writer = self._sock.makefile("wb")

    def close(self) -> None:
        """Best-effort cleanup of socket and buffered streams."""
        try:
            self._writer.close()
        except Exception:
            pass
        try:
            self._reader.close()
        except Exception:
            pass
        try:
            self._sock.close()
        except Exception:
            pass

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def encrypt(self, message: bytes) -> bytes:
        """Request server-side encryption and return raw ciphertext bytes."""
        self._send_line(b"ENCRYPT " + base64.b64encode(message))
        line = self._recv_line()
        if not line.startswith(b"CT "):
            raise ValueError(f"unexpected encrypt response: {line!r}")
        return base64.b64decode(line[3:], validate=True)

    def check(self, ciphertext: bytes) -> tuple[bool, int]:
        """Request padding/MAC check and return `(accepted, elapsed_ns)`."""
        send_message: bytes = b"CHECK " + base64.b64encode(ciphertext)

        start = time.perf_counter_ns()
        self._send_line(send_message)
        line = self._recv_line()
        end = time.perf_counter_ns()

        delta_ns = end - start

        if not line:
            raise ConnectionError("connection closed")
        if line == b"OK":
            return True, delta_ns
        if line == b"ERR":
            return False, delta_ns
        raise ValueError(f"unexpected check response: {line!r}")

    def _send_line(self, line: bytes) -> None:
        """Write one protocol line."""
        self._writer.write(line + b"\n")
        self._writer.flush()

    def _recv_line(self) -> bytes:
        """Read one protocol line without the trailing newline."""
        return self._reader.readline().strip()
