from __future__ import annotations

import hashlib
import hmac

from . import crypto


def split_addr(addr: str) -> tuple[str, int]:
    host, port_raw = addr.rsplit(":", 1)
    return host, int(port_raw)


def parse_hex_aes_key(value: str) -> bytes:
    if not value:
        raise ValueError("missing key")
    out = bytes.fromhex(value)
    if len(out) not in (16, 24, 32):
        raise ValueError(f"invalid AES key length {len(out)}")
    return out


def parse_hex_mac_key(value: str) -> bytes:
    if not value:
        raise ValueError("missing key")
    out = bytes.fromhex(value)
    if len(out) == 0:
        raise ValueError("invalid MAC key length 0")
    return out


def parse_csv_floats(raw: str) -> list[float]:
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
    if value < 0:
        raise ValueError("must be non-negative")
    return value / 1000.0


def expected_payload_block(msg: bytes, mac_key: bytes, block_index: int) -> bytes:
    tag = hmac.new(mac_key, msg, hashlib.sha256).digest()
    payload = crypto.pkcs7_pad(msg + tag, crypto.BLOCK_SIZE)
    blocks = len(payload) // crypto.BLOCK_SIZE
    if block_index < 1 or block_index > blocks:
        raise ValueError(f"block index {block_index} out of range [1,{blocks}]")
    start = (block_index - 1) * crypto.BLOCK_SIZE
    return payload[start : start + crypto.BLOCK_SIZE]
