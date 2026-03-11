import unittest

from padding_oracle import cli, crypto, services, utils


class CliHelpersTests(unittest.TestCase):
    def test_resolve_server_keys_generates_when_omitted(self) -> None:
        enc_key, mac_key = cli._resolve_server_keys(None, None)
        self.assertEqual(len(enc_key), 32)
        self.assertEqual(len(mac_key), 32)

    def test_resolve_server_keys_requires_both_or_none(self) -> None:
        with self.assertRaises(ValueError):
            cli._resolve_server_keys("00" * 32, None)
        with self.assertRaises(ValueError):
            cli._resolve_server_keys(None, "11" * 32)

    def test_resolve_target_block_index_manual_range(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)
        msg = utils.random_message_from_kb(0.02)
        ciphertext = service.encrypt(msg)
        default_block_index, _ = utils.choose_single_block_target(ciphertext, msg_len=len(msg))

        block_index, name = cli._resolve_target_block_index(
            ciphertext=ciphertext,
            msg_len=len(msg),
            requested=default_block_index,
        )
        self.assertEqual(block_index, default_block_index)
        self.assertEqual(name, "manual_payload_block")

    def test_resolve_target_block_index_rejects_out_of_range(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)
        msg = b"hello world"
        ciphertext = service.encrypt(msg)
        num_blocks = len(ciphertext) // crypto.BLOCK_SIZE

        with self.assertRaises(ValueError):
            cli._resolve_target_block_index(
                ciphertext=ciphertext,
                msg_len=len(msg),
                requested=0,
            )
        with self.assertRaises(ValueError):
            cli._resolve_target_block_index(
                ciphertext=ciphertext,
                msg_len=len(msg),
                requested=num_blocks,
            )

    def test_resolve_target_block_index_defaults_to_fourth_last_payload_block(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)
        msg = b"abc" * 11
        ciphertext = service.encrypt(msg)

        block_index, name = cli._resolve_target_block_index(
            ciphertext=ciphertext,
            msg_len=len(msg),
            requested=None,
        )
        num_blocks = len(ciphertext) // crypto.BLOCK_SIZE
        self.assertEqual(block_index, num_blocks - 4)
        self.assertEqual(name, "fourth_last_payload_block")

    def test_resolve_target_block_index_falls_back_to_first_payload_block(self) -> None:
        ciphertext = b"\x00" * (4 * crypto.BLOCK_SIZE)  # IV + three payload blocks
        block_index, name = cli._resolve_target_block_index(
            ciphertext=ciphertext,
            msg_len=0,
            requested=None,
        )
        self.assertEqual(block_index, 1)
        self.assertEqual(name, "first_payload_block_fallback")

    def test_resolve_target_block_index_defaults_to_only_payload_block_when_needed(self) -> None:
        ciphertext = b"\x00" * (2 * crypto.BLOCK_SIZE)  # IV + one payload block
        block_index, name = cli._resolve_target_block_index(
            ciphertext=ciphertext,
            msg_len=0,
            requested=None,
        )
        self.assertEqual(block_index, 1)
        self.assertEqual(name, "only_payload_block")

    def test_decode_recovered_text_uses_replacement(self) -> None:
        self.assertEqual(cli._decode_recovered_text(b"abc"), "abc")
        self.assertIn("\ufffd", cli._decode_recovered_text(bytes.fromhex("61ff62")))

    def test_expected_message_prefix_for_block(self) -> None:
        msg = b"0123456789abcdefXYZ"
        self.assertEqual(cli._expected_message_prefix_for_block(msg, 1), b"0123456789abcdef")
        self.assertEqual(cli._expected_message_prefix_for_block(msg, 2), b"XYZ")
        self.assertEqual(cli._expected_message_prefix_for_block(msg, 3), b"")


if __name__ == "__main__":
    unittest.main()
