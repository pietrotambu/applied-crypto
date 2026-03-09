"""Shared parsing, sizing, and command-construction helpers."""

import secrets
import string

from . import crypto, services


def split_addr(addr: str) -> tuple[str, int]:
    """Split `host:port` into `(host, port)`."""
    host, port_raw = addr.rsplit(":", 1)
    return host, int(port_raw)


def parse_hex_aes_key(value: str) -> bytes:
    """Parse and validate a hexadecimal AES key."""
    if not value:
        raise ValueError("missing key")
    out = bytes.fromhex(value)
    if len(out) not in (16, 24, 32):
        raise ValueError(f"invalid AES key length {len(out)}")
    return out


def parse_hex_mac_key(value: str) -> bytes:
    """Parse and validate a non-empty hexadecimal MAC key."""
    if not value:
        raise ValueError("missing key")
    out = bytes.fromhex(value)
    if len(out) == 0:
        raise ValueError("invalid MAC key length 0")
    return out


def parse_csv_floats(raw: str) -> list[float]:
    """Parse a comma-separated list of non-negative floats."""
    values: list[float] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        value = float(part)
        if value < 0:
            raise ValueError("negative values are not allowed")
        values.append(value)
    if not values:
        raise ValueError("no values provided")
    return values


def ms_to_seconds(value: float) -> float:
    """Convert milliseconds to seconds with non-negative validation."""
    if value < 0:
        raise ValueError("must be non-negative")
    return value / 1000.0


def kb_to_bytes(value_kb: float) -> int:
    """Convert a positive size in KB to an integer number of bytes."""
    if value_kb <= 0:
        raise ValueError("message size must be > 0 KB")
    out = int(value_kb * 1024)
    if out < 1:
        raise ValueError("message size too small")
    return out


def random_message_from_kb(value_kb: float) -> bytes:
    """Build a random ASCII message of approximately `value_kb` kilobytes."""
    size_bytes = kb_to_bytes(value_kb)
    alphabet = string.ascii_letters + string.digits
    out = "".join(secrets.choice(alphabet) for _ in range(size_bytes))
    return out.encode("ascii")


def proxy_command_args(listen_addr: str, target_addr: str, jitter_ms: float) -> list[str]:
    """Construct CLI args for launching the local jitter proxy."""
    return [
        "proxy",
        "--listen",
        listen_addr,
        "--target",
        target_addr,
        "--jitter-ms",
        f"{jitter_ms}",
    ]


def server_command_args(
    addr: str,
    enc_key: bytes,
    mac_key: bytes,
    timing_work_factor: int = 0,
    mac_alg: str = "sha256",
    mac_tag_bytes: int = 32,
) -> list[str]:
    """Construct CLI args for launching the vulnerable server process."""
    args = [
        "server",
        "--addr",
        addr,
        "--enc-key",
        enc_key.hex(),
        "--mac-key",
        mac_key.hex(),
    ]
    factor = max(1, int(timing_work_factor))
    if factor != 1:
        args.extend(["--timing-work-factor", str(factor)])
    if mac_alg != "sha256":
        args.extend(["--mac-alg", mac_alg])
    if int(mac_tag_bytes) != 32:
        args.extend(["--mac-tag-bytes", str(int(mac_tag_bytes))])
    return args


def expected_payload_padded(
    msg: bytes,
    mac_key: bytes,
    mac_alg: str = "sha256",
    mac_tag_bytes: int = 32,
) -> bytes:
    """Return `PKCS7(msg || tag)` for the configured MAC settings."""
    tag = services.compute_mac_tag(mac_alg, mac_key, msg, mac_tag_bytes)
    return crypto.pkcs7_pad(msg + tag, crypto.BLOCK_SIZE)


def expected_payload_block(
    msg: bytes,
    mac_key: bytes,
    block_index: int,
    mac_alg: str = "sha256",
    mac_tag_bytes: int = 32,
) -> bytes:
    """Return one 1-based block from the padded payload."""
    payload = expected_payload_padded(msg, mac_key, mac_alg=mac_alg, mac_tag_bytes=mac_tag_bytes)
    blocks = len(payload) // crypto.BLOCK_SIZE
    if block_index < 1 or block_index > blocks:
        raise ValueError(f"block index {block_index} out of range [1,{blocks}]")
    start = (block_index - 1) * crypto.BLOCK_SIZE
    return payload[start: start + crypto.BLOCK_SIZE]


def choose_single_block_target(
    ciphertext: bytes,
    msg_len: int,
    mac_tag_bytes: int,
) -> tuple[int, str]:
    """Pick attack target block while avoiding pure full-padding tail blocks."""
    if len(ciphertext) < 2 * crypto.BLOCK_SIZE or len(ciphertext) % crypto.BLOCK_SIZE != 0:
        raise ValueError("ciphertext must include IV and be a multiple of 16 bytes")
    if msg_len < 0:
        raise ValueError("msg_len must be >= 0")
    if mac_tag_bytes < 1:
        raise ValueError("mac_tag_bytes must be >= 1")

    num_blocks = len(ciphertext) // crypto.BLOCK_SIZE
    last_block_index = num_blocks - 1
    payload_len = msg_len + mac_tag_bytes

    # If payload is already block-aligned, PKCS#7 appends a full 0x10 block.
    # Skip that pure-padding final block and target the previous block instead.
    if payload_len % crypto.BLOCK_SIZE == 0:
        if last_block_index <= 1:
            raise ValueError("ciphertext too short to skip full-padding last block")
        return last_block_index - 1, "second_last_payload_block"
    return last_block_index, "last_payload_block"
