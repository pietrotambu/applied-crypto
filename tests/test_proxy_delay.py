import unittest
from unittest.mock import Mock, patch

from padding_oracle import proxy


class ProxyDelayTests(unittest.TestCase):
    def test_sleep_precise_tiny_delay_avoids_sleep(self) -> None:
        with patch("padding_oracle.proxy.time.sleep") as sleep_mock:
            with patch("padding_oracle.proxy.time.perf_counter_ns", side_effect=[0, 2_000]):
                proxy._sleep_precise(1.5e-6)
        sleep_mock.assert_not_called()

    def test_sleep_precise_long_delay_uses_sleep(self) -> None:
        with patch("padding_oracle.proxy.time.sleep") as sleep_mock:
            with patch("padding_oracle.proxy.time.perf_counter_ns", side_effect=[0, 2_000_000]):
                proxy._sleep_precise(1e-3)
        sleep_mock.assert_called_once()
        self.assertGreater(sleep_mock.call_args.args[0], 0.0)

    def test_delay_clamps_negative_total(self) -> None:
        rng = Mock()
        rng.uniform.return_value = -0.002
        with patch("padding_oracle.proxy._sleep_precise") as wait_mock:
            proxy._delay(rng, base_delay_s=0.001, jitter_s=0.002)
        wait_mock.assert_not_called()

    def test_delay_positive_total_uses_precise_wait(self) -> None:
        rng = Mock()
        rng.uniform.return_value = 0.0005
        with patch("padding_oracle.proxy._sleep_precise") as wait_mock:
            proxy._delay(rng, base_delay_s=0.001, jitter_s=0.002)
        wait_mock.assert_called_once()
        self.assertAlmostEqual(wait_mock.call_args.args[0], 0.0015, places=9)


if __name__ == "__main__":
    unittest.main()
