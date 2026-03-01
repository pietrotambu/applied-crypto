import unittest

from padding_oracle import crypto, services
from padding_oracle.timing_stability import _p_greater, _summarize, _tamper_mac, _tamper_padding


class TimingStabilityTests(unittest.TestCase):
    def test_probability_greater(self) -> None:
        self.assertGreater(_p_greater([10, 11, 12], [1, 2, 3]), 0.99)
        self.assertLess(_p_greater([1, 2, 3], [10, 11, 12]), 0.01)

    def test_summarize(self) -> None:
        stats = _summarize([10, 20, 30, 40])
        self.assertEqual(stats.count, 4)
        self.assertEqual(stats.min_ns, 10)
        self.assertEqual(stats.max_ns, 40)
        self.assertGreater(stats.p99_ns, stats.p95_ns)

    def test_tamper_helpers(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)
        ct = service.encrypt(b"stability")
        self.assertNotEqual(_tamper_mac(ct), ct)
        self.assertNotEqual(_tamper_padding(ct), ct)


if __name__ == "__main__":
    unittest.main()
