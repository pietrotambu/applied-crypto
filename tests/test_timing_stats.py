import unittest

from padding_oracle import crypto, services
from padding_oracle.timing_stats import _collect_samples, _summarize, _tampered_ciphertext


class TimingStatsTests(unittest.TestCase):
    def test_summarize_many_values(self) -> None:
        summary = _summarize([1_000_000, 2_000_000, 3_000_000])
        self.assertEqual(summary.count, 3)
        self.assertEqual(summary.min_ms, 1.0)
        self.assertEqual(summary.avg_ms, 2.0)
        self.assertEqual(summary.max_ms, 3.0)

    def test_collect_samples_valid(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)
        ciphertext = service.encrypt(b"timing stats")

        ok_count, rows = _collect_samples(service, ciphertext, trials=5, warmup=1)
        self.assertEqual(ok_count, 5)
        self.assertEqual(len(rows["total_ns"]), 5)
        self.assertTrue(all(v >= 0 for v in rows["total_ns"]))

    def test_tampered_ciphertext_changes_bytes(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)
        ciphertext = service.encrypt(b"x")
        tampered = _tampered_ciphertext(ciphertext)
        self.assertNotEqual(tampered, ciphertext)
        self.assertEqual(len(tampered), len(ciphertext))


if __name__ == "__main__":
    unittest.main()
