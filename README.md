# CBC Padding Oracle Project (Python, Tasks 2, 3, 4)

This repository implements:
- Task 2: classic CBC padding-oracle plaintext recovery (boolean oracle).
- Task 3: timing-oracle attack against a MAC-then-encrypt CBC receiver.
- Task 4: repeated timing-attack trials to measure robustness under external network noise.

The codebase intentionally has no in-code proxy/jitter layer. For Task 4 noise experiments,
use external setup (for example two machines on a LAN, or Linux `tc netem`).

## Repository Structure

- `padding_oracle/crypto.py`: AES-CBC and PKCS#7 primitives.
- `padding_oracle/services.py`: vulnerable services for Task 2 and Task 3/4.
- `padding_oracle/protocol.py`: line-based TCP protocol (`ENCRYPT`, `CHECK`).
- `padding_oracle/attacks/`: boolean and timing attack implementations.
- `padding_oracle/process.py`: subprocess/socket helpers for orchestration.
- `padding_oracle/cli.py`: command entrypoints for `server`/`victim`, `attacker`, `boolean`, and `timing`.
- `padding_oracle/timing_stats.py`: long-path vs short-path timing separation utility.
- `scripts/task4_baseline.sh`: baseline Task 4 run script.
- `scripts/task4_netem_lo_sweep.sh`: loopback netem sweep script for Task 4.
- `tests/`: unit tests.

## Quickstart (Make-first)

Prerequisites:
- Python 3.10+
- `make`

```bash
make help
make venv
make install
```

Optional editable install:
```bash
make install-editable
```

Run task demos:
```bash
make boolean
make timing
make timing ARGS='--message-kb 4'
make timing ARGS="--message 'hello world'"
```

Run split victim/attacker mode:
```bash
make victim ARGS='--addr 0.0.0.0:4000'
make attacker ARGS='--addr 127.0.0.1:4000 --message-kb 1'
```

Run a custom CLI command:
```bash
make run COMMAND='boolean --message "hello"'
make run COMMAND='timing --message-kb 1'
```

## Distributed Victim/Attacker Setup (Two Machines)

1. Start victim/oracle on machine B:
```bash
python3 -m padding_oracle.cli victim --addr 0.0.0.0:4000
```
You can also pin keys explicitly:
```bash
python3 -m padding_oracle.cli victim \
  --addr 0.0.0.0:4000 \
  --enc-key <hex_aes_key> \
  --mac-key <hex_mac_key>
```

2. Run attacker on machine A against machine B:
```bash
python3 -m padding_oracle.cli attacker --addr <victim_ip>:4000 --message-kb 16
```

3. Optional validation (if attacker knows victim MAC key):
```bash
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

Example extraction from victim logs:
```bash
MAC_KEY_HEX="$(rg '^MAC_KEY_HEX=' victim.log | tail -n1 | cut -d= -f2)"
python3 -m padding_oracle.cli attacker \
  --addr <victim_ip>:4000 \
  --message-kb 16 \
  --verify-mac-key "$MAC_KEY_HEX"
```

## Running Tests

Run all unit tests:
```bash
make test
```

## Task 4 Runs (No Internal Jitter)

There is no `task4` CLI subcommand. Task 4 is handled by running repeated `timing`
executions under different external network conditions.

Use helper scripts:
```bash
./scripts/task4_baseline.sh
./scripts/task4_netem_lo_sweep.sh
```

Optional tuning:
```bash
TRIALS=5 MESSAGE_KB=2 ./scripts/task4_baseline.sh
TRIALS=5 MESSAGE_KB=2 ./scripts/task4_netem_lo_sweep.sh
```

`task4_netem_lo_sweep.sh` applies noise externally on loopback via `tc netem` and executes repeated `timing` runs per profile.

## Timing Statistics

Compare long-path vs short-path timing over many checks:
```bash
make timing-stats ARGS='--trials 10000 --warmup 500 --message-kb 1'
make timing-stats ARGS="--trials 10000 --warmup 500 --message 'hello world'"
```
