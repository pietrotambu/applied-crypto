import unittest

from padding_oracle import attacks, crypto


class TimingAttackTests(unittest.TestCase):
    def test_recover_block_timing_synthetic_oracle(self) -> None:
        prev = bytes([0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x13, 0x57, 0x9B, 0xDF, 0x11, 0x22, 0x33, 0x44])
        curr = bytes(16)

        intermediate = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0x10, 0x20, 0x30, 0x40, 0x7F, 0x6E, 0x5D, 0x4C, 0x3B, 0x2A, 0x19, 0x08])
        expected = bytes(i ^ p for i, p in zip(intermediate, prev))

        def oracle(forged: bytes) -> int:
            candidate_prev = forged[:16]
            plain = bytes(i ^ c for i, c in zip(intermediate, candidate_prev))
            try:
                crypto.pkcs7_unpad(plain, crypto.BLOCK_SIZE)
                return 5_000_000
            except Exception:
                return 1_000_000

        recovered, _queries = attacks.recover_block_timing(
            prev,
            curr,
            oracle,
            attacks.TimingConfig(initial_samples=1, refine_samples=2, top_candidates=4),
        )
        self.assertEqual(recovered, expected)


if __name__ == "__main__":
    unittest.main()
