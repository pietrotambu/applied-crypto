from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def free_local_addr() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()
        return f"{host}:{port}"


def _set_affinity_self(cpu: int) -> None:
    if cpu < 0:
        raise ValueError("cpu must be >= 0")
    if not hasattr(os, "sched_setaffinity"):
        raise RuntimeError("CPU affinity is not supported on this platform")
    os.sched_setaffinity(0, {cpu})


def set_current_process_affinity(cpu: int | None) -> None:
    if cpu is None:
        return
    _set_affinity_self(cpu)


def _make_affinity_preexec(cpu: int | None):
    if cpu is None:
        return None

    def _preexec() -> None:
        _set_affinity_self(cpu)

    return _preexec


def start_self_process(args: list[str], cpu: int | None = None) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "padding_oracle.cli", *args],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=_make_affinity_preexec(cpu),
    )


def wait_for_tcp(addr: str, timeout: float = 3.0) -> None:
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
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=1.0)
