import secrets
import string

from . import crypto, services


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


def kb_to_bytes(value_kb: float) -> int:
    if value_kb <= 0:
        raise ValueError("message size must be > 0 KB")
    out = int(value_kb * 1024)
    if out < 1:
        raise ValueError("message size too small")
    return out


def random_message_from_kb(value_kb: float) -> bytes:
    size_bytes = kb_to_bytes(value_kb)
    alphabet = string.ascii_letters + string.digits
    out = "".join(secrets.choice(alphabet) for _ in range(size_bytes))
    return out.encode("ascii")


def proxy_command_args(listen_addr: str, target_addr: str, jitter_ms: float) -> list[str]:
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
    tag = services.compute_mac_tag(mac_alg, mac_key, msg, mac_tag_bytes)
    return crypto.pkcs7_pad(msg + tag, crypto.BLOCK_SIZE)


def expected_payload_block(
    msg: bytes,
    mac_key: bytes,
    block_index: int,
    mac_alg: str = "sha256",
    mac_tag_bytes: int = 32,
) -> bytes:
    payload = expected_payload_padded(msg, mac_key, mac_alg=mac_alg, mac_tag_bytes=mac_tag_bytes)
    blocks = len(payload) // crypto.BLOCK_SIZE
    if block_index < 1 or block_index > blocks:
        raise ValueError(f"block index {block_index} out of range [1,{blocks}]")
    start = (block_index - 1) * crypto.BLOCK_SIZE
    return payload[start: start + crypto.BLOCK_SIZE]
