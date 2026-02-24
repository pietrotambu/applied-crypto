# CBC Padding Oracle Project (Python, Tasks 2, 3, 4)

This is a standalone Python 3 repository implementing:
- Task 2: classic CBC padding-oracle plaintext recovery (boolean oracle).
- Task 3: timing-oracle attack against a MAC-then-encrypt CBC receiver.
- Task 4: benchmark of timing attack robustness under injected localhost noise.

Design constraints:
- Multiprocess communication over `127.0.0.1` is used for task 3 and task 4.
- No multithreaded attack flow is used.

## Compilation and Installation

Prerequisites:
- Python 3.10+
- `pip`

Install dependencies:
```bash
python3 -m pip install -r requirements.txt
```

Optional editable install (adds `padding-oracle` command):
```bash
python3 -m pip install -e .
```

Run task 2 demo:
```bash
python3 -m padding_oracle.cli task2
```

Run task 3 demo (spawns localhost server process automatically):
```bash
python3 -m padding_oracle.cli task3
```

## Running the test cases

Run all tests:
```bash
python3 -m unittest discover -s tests -v
```

Interpretation:
- `test_recover_plaintext_boolean` validates full plaintext recovery for task 2.
- `test_recover_block_timing_synthetic_oracle` validates timing-based byte recovery logic.

## Running benchmarks

Run task 4 benchmark with configurable jitter levels (milliseconds, decimals allowed):
```bash
python3 -m padding_oracle.cli task4 --trials 3 --jitters-ms 1,2,3,4
```

Recommended robust settings for sub-millisecond jitter:
```bash
python3 -m padding_oracle.cli task4 \
  --trials 3 \
  --jitters-ms 2,4,8,12 \
  --initial-samples 2 \
  --refine-samples 10 \
  --top-k 12 \
  --mac-work 8000
```

Output format example:
```text
task4: timing-attack robustness under injected localhost noise
server=127.0.0.1:43977 base_delay_ms=0.000000 trials=3
jitter_ms success_rate avg_queries avg_elapsed_ms
2.000000 1.00 10112.0 31830.53
4.000000 0.99 10112.0 38220.91
8.000000 0.67 10112.0 49100.61
...
```

Interpretation:
- `success_rate`: fraction of successful plaintext block recoveries.
- `avg_queries`: average oracle calls per trial.
- `avg_elapsed_ms`: average wall-clock attack time.
- Increasing jitter generally lowers success and increases runtime.
