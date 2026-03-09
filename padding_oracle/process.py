"""Subprocess and socket helpers used by task orchestration commands."""

import sys
import time
import socket
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def free_local_addr() -> str:
    """Return a currently-free localhost address in `host:port` format."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()
        return f"{host}:{port}"


def start_self_process(args: list[str]) -> subprocess.Popen:
    """Spawn this package's CLI module with provided argument list."""
    return subprocess.Popen(
        [sys.executable, "-m", "padding_oracle.cli", *args],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_for_tcp(addr: str, timeout: float = 3.0) -> None:
    """Wait until a TCP endpoint starts accepting connections."""
    host, port_raw = addr.rsplit(":", 1)
    port = int(port_raw)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {addr}")


def stop_process(proc: subprocess.Popen) -> None:
    """Stop a subprocess gracefully, then force-kill if needed."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=1.0)
