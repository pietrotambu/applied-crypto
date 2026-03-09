import unittest

from padding_oracle import attacks, crypto, services, utils


VALID_PADDING_NS = 2_000_000
INVALID_PADDING_NS = 1_000_000


def _split_blocks(ciphertext: bytes) -> list[bytes]:
    return [
        ciphertext[i : i + crypto.BLOCK_SIZE]
        for i in range(0, len(ciphertext), crypto.BLOCK_SIZE)
    ]


def _payload_block(padded_payload: bytes, block_index: int) -> bytes:
    start = (block_index - 1) * crypto.BLOCK_SIZE
    return padded_payload[start : start + crypto.BLOCK_SIZE]


def _deterministic_timing_oracle(enc_key: bytes) -> attacks.TimingOracle:
    def timing_oracle(ciphertext: bytes) -> int:
        try:
            padded = crypto.decrypt_cbc_raw(enc_key, ciphertext)
            pad_len = padded[-1]
            crypto.pkcs7_unpad(padded, crypto.BLOCK_SIZE)
        except Exception:
            return INVALID_PADDING_NS
        # Keep valid-padding samples strictly above invalid ones while
        # disfavoring larger pad lengths (e.g., full-block 0x10 ambiguity).
        return VALID_PADDING_NS + (crypto.BLOCK_SIZE - pad_len)

    return timing_oracle


def _fast_config() -> attacks.TimingConfig:
    return attacks.TimingConfig(
        initial_samples=1,
        refine_samples=1,
        top_candidates=8,
        confidence_z=1.0,
        min_compare_samples=2,
        max_queries_per_byte=20_000,
    )


class TimingAttackTests(unittest.TestCase):
    def test_recover_block_timing_from_service_oracle(self) -> None:
        key = crypto.random_bytes(32)
        service = services.BasicOracleService(key)
        msg = utils.random_message_from_kb(0.04)
        ciphertext = service.encrypt(msg)
        blocks = _split_blocks(ciphertext)
        expected = _payload_block(crypto.pkcs7_pad(msg, crypto.BLOCK_SIZE), 1)

        recovered, _queries = attacks.recover_block_timing(
            blocks[0],
            blocks[1],
            _deterministic_timing_oracle(key),
            _fast_config(),
        )
        self.assertEqual(recovered, expected)

    def test_recover_ciphertext_block_timing_preserves_prefix(self) -> None:
        key = crypto.random_bytes(32)
        service = services.BasicOracleService(key)
        msg = utils.random_message_from_kb(0.04)
        ciphertext = service.encrypt(msg)
        expected_padded = crypto.pkcs7_pad(msg, crypto.BLOCK_SIZE)

        block_index = 2
        expected = _payload_block(expected_padded, block_index)
        prefix_len = (block_index - 1) * crypto.BLOCK_SIZE
        expected_prefix = ciphertext[:prefix_len]
        seen_prefixes: list[bytes] = []
        base_oracle = _deterministic_timing_oracle(key)

        def oracle(forged: bytes) -> int:
            seen_prefixes.append(forged[:prefix_len])
            return base_oracle(forged)

        recovered, _queries = attacks.recover_ciphertext_block_timing(
            ciphertext,
            block_index,
            oracle,
            _fast_config(),
        )
        self.assertEqual(recovered, expected)
        self.assertTrue(seen_prefixes)
        self.assertTrue(all(prefix == expected_prefix for prefix in seen_prefixes))

    def test_recover_plaintext_timing_full_message(self) -> None:
        key = crypto.random_bytes(32)
        service = services.BasicOracleService(key)
        msg = utils.random_message_from_kb(0.03)
        ciphertext = service.encrypt(msg)
        expected_plaintext = crypto.pkcs7_pad(msg, crypto.BLOCK_SIZE)

        recovered, _queries = attacks.recover_plaintext_timing(
            ciphertext,
            _deterministic_timing_oracle(key),
            _fast_config(),
        )
        self.assertEqual(recovered, expected_plaintext)

    def test_recover_block_timing_disambiguates_full_padding_last_byte(self) -> None:
        key = crypto.random_bytes(32)
        service = services.BasicOracleService(key)
        msg = b"A" * crypto.BLOCK_SIZE
        ciphertext = service.encrypt(msg)
        blocks = _split_blocks(ciphertext)
        target_block_index = len(blocks) - 1
        expected_plain = _payload_block(
            crypto.pkcs7_pad(msg, crypto.BLOCK_SIZE),
            target_block_index,
        )
        self.assertEqual(expected_plain, bytes([crypto.BLOCK_SIZE]) * crypto.BLOCK_SIZE)

        recovered, _queries = attacks.recover_ciphertext_block_timing(
            ciphertext,
            target_block_index,
            _deterministic_timing_oracle(key),
            _fast_config(),
        )
        self.assertEqual(recovered, expected_plain)

    def test_recover_block_timing_reports_progress(self) -> None:
        key = crypto.random_bytes(32)
        service = services.BasicOracleService(key)
        msg = b"progress callback test"
        ciphertext = service.encrypt(msg)
        blocks = _split_blocks(ciphertext)

        updates: list[int] = []
        _recovered, queries = attacks.recover_block_timing(
            blocks[0],
            blocks[1],
            _deterministic_timing_oracle(key),
            _fast_config(),
            progress_callback=updates.append,
        )

        self.assertGreater(len(updates), 0)
        self.assertEqual(updates[-1], queries)
        self.assertTrue(all(earlier <= later for earlier, later in zip(updates, updates[1:])))


if __name__ == "__main__":
    unittest.main()
