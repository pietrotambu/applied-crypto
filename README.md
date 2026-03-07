# CBC Padding Oracle Project (Python, Tasks 2, 3, 4)

This is a standalone Python 3 repository implementing:
- Task 2: classic CBC padding-oracle plaintext recovery (boolean oracle).
- Task 3: timing-oracle attack against a MAC-then-encrypt CBC receiver.
- Task 4: benchmark of timing attack robustness under injected localhost noise.

Design constraints:
- Multiprocess communication over `127.0.0.1` is used for task 3 and task 4.
- No multithreaded attack flow is used.

## Quickstart (Make-first)

Prerequisites:
- Python 3.10+
- `make`

Show available commands:
```bash
make help
```

Create local virtual environment:
```bash
make venv
```

Install dependencies:
```bash
make install
```

Optional editable install (adds `padding-oracle` command):
```bash
make install-editable
```

Run task 2 demo:
```bash
make task2
```

Run task 3 demo (spawns localhost server process automatically):
```bash
make task3
```

Run a fully custom CLI command:
```bash
make run COMMAND='task4 --trials 3 --jitters-ms 0,0.01,0.02'
```

Equivalent direct Python commands (if you do not want to use `make`):
```bash
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
python3 -m padding_oracle.cli task2
python3 -m padding_oracle.cli task3
```

## Running the test cases

Run all tests:
```bash
make test
```

Interpretation:
- `test_recover_plaintext_boolean` validates full plaintext recovery for task 2.
- `test_recover_block_timing_synthetic_oracle` validates timing-based byte recovery logic.

## Running benchmarks

Run task 4 benchmark with configurable jitter levels (milliseconds, decimals allowed):
```bash
make task4 ARGS='--trials 3 --jitters-ms 1,2,3,4'
```

Recommended robust settings for sub-millisecond jitter:
```bash
make task4 ARGS='--trials 3 --jitters-ms 2,4,8,12 --initial-samples 2 --refine-samples 10 --top-k 12'
```

Output format example:
```text
task4: timing-attack robustness under injected localhost noise
server=127.0.0.1:43977 trials=3
jitter_ms success_rate avg_queries avg_elapsed_ms completed_trials error_trials successes total_trials
2.000000 1.00000 10112.0 13500.28 3 0 3 3
4.000000 1.00000 10112.0 25351.21 3 0 3 3
8.000000 0.67000 10112.0 49087.97 3 0 2 3
12.000000 0.00000 10112.0 69397.78 3 0 0 3

...
```

Interpretation:
- `success_rate`: fraction of successful plaintext block recoveries over all requested trials.
- `avg_queries`: average oracle calls over completed trials (prints `nan` if none completed).
- `avg_elapsed_ms`: average wall-clock attack time over completed trials (prints `nan` if none completed).
- `completed_trials` and `error_trials`: help distinguish attack failures from runtime/proxy errors.
- `successes` and `total_trials`: explicit success count per jitter row.
- Increasing jitter generally lowers success and increases runtime.

## Timing Statistics Script

Analyze task4-style timing branch separation over many retries (through server + proxy):
```bash
make timing-stats ARGS='--trials 10000 --warmup 500 --jitter-ms 0.01'
```

The report is intentionally simple and prints:
- `long_journey`: padding valid, MAC computed (MAC-fail path)
- `short_journey`: padding fails early, no MAC
- `min_ms`, `avg_ms`, `max_ms` for each journey
- `delta_avg_ms(long-short)` as the key signal
