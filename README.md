# CBC Padding Oracle Project

This project has two main parts:
- Task 2: classic CBC padding-oracle plaintext recovery (boolean oracle).
- Task 3/4: timing-oracle block recovery against MAC-then-encrypt receiver.

## Repository Structure

- `padding_oracle/crypto.py`: AES-CBC and PKCS#7 functions.
- `padding_oracle/services.py`: vulnerable oracle/receiver services.
- `padding_oracle/protocol.py`: TCP protocol (`ENCRYPT`, `CHECK`).
- `padding_oracle/attacks/`: boolean and timing attack code.
- `padding_oracle/cli.py`: CLI commands (`server`, `victim`, `boolean`, `timing`, `attacker`).
- `padding_oracle/timing_stats.py`: benchmark for long path vs short path.
- `padding_oracle/noise_experiment.py`: benchmark with injected timing noise.
- `tests/`: unit tests.

## Compilation and Installation

This is a Python project, so there is no compile step before running.
Installation means creating virtual environment and installing packages.

Prerequisites:
- Python `>=3.10` (in `Makefile`, default is `python3.12` with `SYSTEM_PYTHON`).
- `make` (optional, but useful).

Setup with `make`:
```bash
make venv
make install
```

Setup without `make`:
```bash
python3 -m venv .venv

# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Optional editable install (adds `padding-oracle` command):
```bash
# with make
make install-editable

# without make
python3 -m pip install -e .
```

Quick sanity check:
```bash
.venv/bin/python -m padding_oracle.cli --help
```

## Running the test cases

Run all tests:
```bash
# with make
make test

# without make
.venv/bin/python -m unittest discover -s tests -v
```

How to interpret test output:
- If one test is good, it ends with `... ok`.
- At the end you should see `OK` for full pass.
- If you see `FAIL` or `ERROR`, tests did not pass.
- Non-zero exit code also means there is failing/error test.

## Running benchmarks

### 1) Timing path-separation benchmark (`timing_stats.py`)

This benchmark measures timing gap between two cases:
- `long path`: padding is valid, then MAC check runs (and fails after).
- `short path`: padding is invalid, so reject happens early.

Commands:
```bash
# with make
make timing-stats ARGS='--trials 10000 --warmup 500 --message-kb 1'
make timing-stats ARGS="--trials 10000 --warmup 500 --message 'hello world'"

# without make
.venv/bin/python -m padding_oracle.timing_stats --trials 10000 --warmup 500 --message-kb 1
.venv/bin/python -m padding_oracle.timing_stats --trials 10000 --warmup 500 --message "hello world"
```

How to interpret output:
- `delta_avg_ms (long-short)`: if positive, long path is slower (this is expected leak direction).
- `signal: LONG>SHORT`: expected sign, usually good for attack signal.
- `signal: LONG<SHORT` or very close to zero: weak signal, use more trials or less noise.

### 2) Noise robustness benchmark (`noise_experiment.py`)

This benchmark repeats timing recovery with added Gaussian jitter.
It reports success rate and cost.

Commands:
```bash
# with make
make noise-experiment
make noise-experiment ARGS='--message-kb 1 --runs 5 --jitter-levels-us 0 10 25 50 100 250'

# without make
.venv/bin/python -m padding_oracle.noise_experiment
.venv/bin/python -m padding_oracle.noise_experiment --message-kb 1 --runs 5 --jitter-levels-us 0 10 25 50 100 250
```

How to interpret output:
- Each run prints `success`, `queries`, and `elapsed_ms`.
- Final table has:
  - `jitter_us`: jitter level (microseconds).
  - `success_rate`: how many runs succeeded at this jitter.
  - `avg_queries`: average oracle queries.
  - `avg_time_ms`: average runtime.
- Script also writes detailed rows to `noise_results.csv`.
- Usually with larger jitter, `success_rate` goes down and query/time go up.

## Task Demos

Run local demos:
```bash
# boolean demo
make boolean
.venv/bin/python -m padding_oracle.cli boolean

# timing demo
make timing
.venv/bin/python -m padding_oracle.cli timing

# timing demo with message size override
make timing ARGS='--message-kb 4'
.venv/bin/python -m padding_oracle.cli timing --message-kb 4
```

## Split Victim/Attacker Setup (Two Machines)

1. Start victim/oracle on machine B:
```bash
# with make
make victim ARGS='--addr 0.0.0.0:4000'

# without make
.venv/bin/python -m padding_oracle.cli victim --addr 0.0.0.0:4000
```

Optional fixed keys:
```bash
# with make
make victim ARGS='--addr 0.0.0.0:4000 --enc-key <hex_aes_key> --mac-key <hex_mac_key>'

# without make
.venv/bin/python -m padding_oracle.cli victim \
  --addr 0.0.0.0:4000 \
  --enc-key <hex_aes_key> \
  --mac-key <hex_mac_key>
```

2. Run attacker on machine A against machine B:
```bash
# with make
make attacker ARGS='--addr <victim_ip>:4000 --message-kb 16'

# without make
.venv/bin/python -m padding_oracle.cli attacker --addr <victim_ip>:4000 --message-kb 16
```

Enable progress logging:
```bash
# with make
make attacker ARGS='--addr <victim_ip>:4000 --message-kb 16 --log-progress'

# without make
.venv/bin/python -m padding_oracle.cli attacker --addr <victim_ip>:4000 --message-kb 16 --log-progress
```

Notes:
- Victim must bind to a reachable interface (`0.0.0.0` or a specific LAN IP).
- Open firewall/security rules for the selected TCP port.
- `timing` is a self-contained localhost demo; `attacker` is the split deployment command.
