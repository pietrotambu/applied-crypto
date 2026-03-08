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

    def test_recover_ciphertext_block_timing_preserves_prefix(self) -> None:
        iv = bytes([0x11] * 16)
        c1 = bytes([0x22] * 16)
        c2 = bytes([0x33] * 16)
        c3 = bytes([0x44] * 16)
        ciphertext = iv + c1 + c2 + c3

        # Recover plaintext block for c2 (block_index=2), keeping iv as prefix.
        block_index = 2
        prefix = ciphertext[:16]
        prev = c1
        intermediate = bytes(
            [0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x16, 0x27, 0x38, 0x49, 0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0xAF]
        )
        expected = bytes(i ^ p for i, p in zip(intermediate, prev))

        def oracle(forged: bytes) -> int:
            self.assertEqual(forged[:16], prefix)
            candidate_prev = forged[16:32]
            plain = bytes(i ^ c for i, c in zip(intermediate, candidate_prev))
            try:
                crypto.pkcs7_unpad(plain, crypto.BLOCK_SIZE)
                return 5_000_000
            except Exception:
                return 1_000_000

        recovered, _queries = attacks.recover_ciphertext_block_timing(
            ciphertext,
            block_index,
            oracle,
            attacks.TimingConfig(initial_samples=1, refine_samples=2, top_candidates=4),
        )
        self.assertEqual(recovered, expected)

    def test_recover_plaintext_timing_full_message(self) -> None:
        iv = bytes([0x10] * 16)
        c1 = bytes([0x21] * 16)
        c2 = bytes([0x32] * 16)
        c3 = bytes([0x43] * 16)
        ciphertext = iv + c1 + c2 + c3

        i1 = bytes([0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0])
        i2 = bytes([0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0])
        i3 = bytes([0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0])
        intermediate_by_curr = {
            c1: i1,
            c2: i2,
            c3: i3,
        }
        expected_prefix_by_curr = {
            c1: b"",
            c2: iv,
            c3: iv + c1,
        }

        p1 = bytes(i ^ p for i, p in zip(i1, iv))
        p2 = bytes(i ^ p for i, p in zip(i2, c1))
        p3 = bytes(i ^ p for i, p in zip(i3, c2))
        expected_plaintext = p1 + p2 + p3

        def oracle(forged: bytes) -> int:
            curr = forged[-16:]
            self.assertIn(curr, intermediate_by_curr)
            self.assertEqual(forged[:-32], expected_prefix_by_curr[curr])
            candidate_prev = forged[-32:-16]

            plain = bytes(i ^ c for i, c in zip(intermediate_by_curr[curr], candidate_prev))
            try:
                crypto.pkcs7_unpad(plain, crypto.BLOCK_SIZE)
                return 5_000_000
            except Exception:
                return 1_000_000

        cfg = attacks.TimingConfig(initial_samples=1, refine_samples=2, top_candidates=4)
        recovered, _queries = attacks.recover_plaintext_timing(
            ciphertext,
            oracle,
            cfg,
        )
        self.assertEqual(recovered, expected_plaintext)

    def test_recover_block_timing_disambiguates_full_padding_last_byte(self) -> None:
        prev = bytes([0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97, 0xA8, 0xB9, 0xCA, 0xDB, 0xEC, 0xFD, 0x10, 0x21, 0x32])
        curr = bytes(16)

        expected_plain = bytes([0x10] * 16)
        intermediate = bytes(p ^ e for p, e in zip(prev, expected_plain))

        def oracle(forged: bytes) -> int:
            candidate_prev = forged[:16]
            plain = bytes(i ^ c for i, c in zip(intermediate, candidate_prev))
            try:
                crypto.pkcs7_unpad(plain, crypto.BLOCK_SIZE)
            except Exception:
                return 1_000_000

            # Intentionally bias full-block padding above pad=1 so the initial
            # ranking would pick the wrong candidate without disambiguation.
            if plain == expected_plain:
                return 6_000_000
            if plain[-1] == 0x01:
                return 5_000_000
            return 4_000_000

        recovered, _queries = attacks.recover_block_timing(
            prev,
            curr,
            oracle,
            attacks.TimingConfig(initial_samples=1, refine_samples=2, top_candidates=8),
        )
        self.assertEqual(recovered, expected_plain)


if __name__ == "__main__":
    unittest.main()
