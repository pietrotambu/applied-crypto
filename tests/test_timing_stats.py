import unittest

from padding_oracle import crypto
from padding_oracle.timing_stats import _collect_samples, _summarize, _tamper_mac, _tamper_padding


class _FakeClient:
    def __init__(self, responses: list[tuple[bool, int]]):
        self._responses = list(responses)
        self._i = 0

    def check(self, _ciphertext: bytes) -> tuple[bool, int]:
        if self._i >= len(self._responses):
            return self._responses[-1]
        response = self._responses[self._i]
        self._i += 1
        return response


class TimingStatsTests(unittest.TestCase):
    def test_summarize_many_values(self) -> None:
        summary = _summarize([1_000_000, 2_000_000, 3_000_000])
        self.assertEqual(summary.count, 3)
        self.assertEqual(summary.min_ms, 1.0)
        self.assertEqual(summary.avg_ms, 2.0)
        self.assertEqual(summary.max_ms, 3.0)

    def test_collect_samples_counts_after_warmup(self) -> None:
        client = _FakeClient(
            responses=[
                (False, 10),  # warmup
                (True, 20),
                (False, 30),
                (True, 40),
            ]
        )
        ok_count, samples = _collect_samples(client, b"ct", trials=3, warmup=1)
        self.assertEqual(ok_count, 2)
        self.assertEqual(samples, [20, 30, 40])

    def test_tamper_helpers_change_bytes(self) -> None:
        ciphertext = crypto.random_bytes(2 * crypto.BLOCK_SIZE)
        mac_tampered = _tamper_mac(ciphertext)
        pad_tampered = _tamper_padding(ciphertext)
        self.assertNotEqual(mac_tampered, ciphertext)
        self.assertNotEqual(pad_tampered, ciphertext)
        self.assertEqual(len(mac_tampered), len(ciphertext))
        self.assertEqual(len(pad_tampered), len(ciphertext))


if __name__ == "__main__":
    unittest.main()
