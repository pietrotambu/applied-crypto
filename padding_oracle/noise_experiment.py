"""Simulated noise experiment for Section 5.4."""

import argparse, random, time
from collections import defaultdict

from padding_oracle import attacks, crypto, process, protocol, utils


def noise_oracle(client: protocol.Client, jitter_std_ns: int):
    """wrap timing oracle with additional noise on delta_ns"""
    def oracle(candidate: bytes):
        _, delta_ns = client.check(candidate)
        if jitter_std_ns > 0:
            return max(0, delta_ns + int(random.gauss(0, jitter_std_ns)))
        return delta_ns
    return oracle


def resolve_target_index(ciphertext: bytes) -> int:
    num_blocks = len(ciphertext) // crypto.BLOCK_SIZE
    last = num_blocks - 1
    if last >= 4:
        return last - 3
    else:
        return 1

def run_trial(server_addr, mac_key, message, jitter_std_ns, config):
    with protocol.Client(server_addr, timeout=2.0) as client:
        ciphertext = client.encrypt(message)
        target_idx = resolve_target_index(ciphertext)
        oracle = noise_oracle(client, jitter_std_ns)
        start = time.perf_counter_ns()
        recovered, queries = attacks.recover_ciphertext_block_timing(
            ciphertext,
            target_idx,
            oracle,
            config,
        )
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

    expected = utils.expected_payload_block(message, mac_key, target_idx)
    return { 
        "jitter_us": jitter_std_ns / 1000, 
        "queries": queries, 
        "elapsed_ms": elapsed_ms,
        "success": recovered == expected,
        }

def run_experiment(message_kb, jitter_levels_us, runs):
    """run experiment at each jitter level and print results as CSV"""
    enc_key = crypto.random_bytes(32)
    mac_key = crypto.random_bytes(32)
    message = utils.random_message_from_kb(message_kb)

    config = attacks.TimingConfig(
        initial_samples = 2, 
        refine_samples = 2, 
        top_candidates = 8, 
        confidence_z = 2.5, 
        min_compare_samples = 10, 
        max_queries_per_byte = 100_000,
        )
    
    server_addr = process.free_local_addr()
    server_process = process.start_self_process(
        utils.server_command_args(server_addr, enc_key, mac_key,)
    )
    process.wait_for_tcp(server_addr, timeout=3.0)

    results = []
    try:
        for jitter_us in jitter_levels_us:
            jitter_ns = int(jitter_us * 1000)
            for run in range(1, runs+1):
                print(f"jitter {jitter_us} us, run {run}/{runs}")
                result = run_trial(server_addr, mac_key, message, jitter_ns, config)
                result["run"] = run
                results.append(result)
                if result["success"]:
                    print(f"success: {result}")
                else:
                    print(f"failure: {result}")
                print(f"queries = {result['queries']:>9d}, time = {result['elapsed_ms']:>9.1f} ms")
    finally:
        process.stop_process(server_process)
    return results


def summary(results):
    """table of results grouped by level of jitter"""
    print(f"{'jitter_us':>10} {'success_rate':>12} {'avg_queries':>12} {'avg_time_ms':>12}")
    grouped = defaultdict(list)
    for result in results:
        grouped[result["jitter_us"]].append(result)
    for jitter_us in sorted(grouped):
        runs = grouped[jitter_us]
        success_rate = sum(r["success"] for r in runs) / len(runs)
        avg_queries = sum(r["queries"] for r in runs) / len(runs)
        avg_time_ms = sum(r["elapsed_ms"] for r in runs) / len(runs)
        print(f"{jitter_us:10.1f} {success_rate:>12} {avg_queries:>12} {avg_time_ms:>12}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--message-kb", type=float, default=1.0)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--jitter-levels-us", type=float, nargs="+", 
                        default=[0, 10, 25, 50, 100, 250, 500, 1000])

    args = parser.parse_args()
    
    print(f"Running noise experiment with message size {args.message_kb} KB")
    print(f"Jitter levels (us): {args.jitter_levels_us}")
    print(f"Runs per level: {args.runs}")

    results = run_experiment(args.message_kb, args.jitter_levels_us, args.runs)
    summary(results)

if __name__ == "__main__":
    main()

