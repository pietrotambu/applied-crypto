# CBC Padding Oracle Project

This repository implements:
- Classic CBC padding-oracle plaintext recovery (boolean oracle).
- Timing-oracle attack against a MAC-then-encrypt CBC receiver.

## Repository Structure

- `padding_oracle/crypto.py`: AES-CBC and PKCS#7 primitives.
- `padding_oracle/services.py`: vulnerable services for Task 2 and Task 3/4.
- `padding_oracle/protocol.py`: line-based TCP protocol (`ENCRYPT`, `CHECK`).
- `padding_oracle/attacks/`: boolean and timing attack implementations.
- `padding_oracle/process.py`: subprocess/socket helpers for orchestration.
- `padding_oracle/cli.py`: command entrypoints for `server`/`victim`, `attacker`, `boolean`, and `timing`.
- `padding_oracle/timing_stats.py`: long-path vs short-path timing separation utility.
- `tests/`: unit tests.

## Quickstart (Make or Direct Python)

Prerequisites:
- Python 3.10+
- `make` (optional)

If you do not have `make`, use the direct Python commands below.

Environment setup with `make`:
```bash
make venv
make install
```

Environment setup without `make`:
```bash
python3 -m venv .venv

# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Optional editable install:
```bash
# with make
make install-editable

# without make
python3 -m pip install -e .
```

Run task demos:
```bash
# boolean demo
make boolean
python3 -m padding_oracle.cli boolean

# timing demo
make timing
python3 -m padding_oracle.cli timing

# timing demo with --message-kb 4
make timing ARGS='--message-kb 4'
python3 -m padding_oracle.cli timing --message-kb 4

# timing demo with explicit message
make timing ARGS="--message 'hello world'"
python3 -m padding_oracle.cli timing --message "hello world"
```

Run split victim/attacker mode:
```bash
# victim
make victim ARGS='--addr 0.0.0.0:4000'
python3 -m padding_oracle.cli victim --addr 0.0.0.0:4000

# attacker
make attacker ARGS='--addr 127.0.0.1:4000 --message-kb 1'
python3 -m padding_oracle.cli attacker --addr 127.0.0.1:4000 --message-kb 1
```

## Distributed Victim/Attacker Setup (Two Machines)

1. Start victim/oracle on machine B:
```bash
# with make
make victim ARGS='--addr 0.0.0.0:4000'
# without make
python3 -m padding_oracle.cli victim --addr 0.0.0.0:4000
```
You can also pin keys explicitly:
```bash
# with make
make victim ARGS='--addr 0.0.0.0:4000 --enc-key <hex_aes_key> --mac-key <hex_mac_key>'
# without make
python3 -m padding_oracle.cli victim \
  --addr 0.0.0.0:4000 \
  --enc-key <hex_aes_key> \
  --mac-key <hex_mac_key>
```

2. Run attacker on machine A against machine B:
```bash
# with make
make attacker ARGS='--addr <victim_ip>:4000 --message-kb 16'
# without make
python3 -m padding_oracle.cli attacker --addr <victim_ip>:4000 --message-kb 16
```
Progress logging:
```bash
# with make
make attacker ARGS='--addr <victim_ip>:4000 --message-kb 16 --log-progress'
# without make
python3 -m padding_oracle.cli attacker --addr <victim_ip>:4000 --message-kb 16 --log-progress
```

3. Optional validation:
```bash
# with make
make attacker ARGS='--addr <victim_ip>:4000 --message-kb 16 --verify-mac-key <hex_mac_key>'
# without make
python3 -m padding_oracle.cli attacker \
  --addr <victim_ip>:4000 \
  --message-kb 16 \
  --verify-mac-key <hex_mac_key>
```

Notes:
- Victim must bind to a reachable interface (`0.0.0.0` or specific LAN IP).
- Ensure firewall/security group allows TCP on the chosen port.
- `timing` remains the self-contained localhost demo; `attacker` is the split-mode command.
- Victim stdout includes parse-friendly lines: `ENC_KEY_HEX=...` and `MAC_KEY_HEX=...`.

## Running Tests

Run all unit tests:
```bash
# with make
make test
# without make
python3 -m unittest discover -s tests -v
```

## Timing Statistics

Compare long-path vs short-path timing over many checks:
```bash
# with make
make timing-stats ARGS='--trials 10000 --warmup 500 --message-kb 1'
make timing-stats ARGS="--trials 10000 --warmup 500 --message 'hello world'"

# without make
python3 -m padding_oracle.timing_stats --trials 10000 --warmup 500 --message-kb 1
python3 -m padding_oracle.timing_stats --trials 10000 --warmup 500 --message "hello world"
```
