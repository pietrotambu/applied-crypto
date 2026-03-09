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

    def test_resolve_target_block_index_uses_default_utility(self) -> None:
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
        expected_index, expected_name = utils.choose_single_block_target(ciphertext, msg_len=len(msg))
        self.assertEqual(block_index, expected_index)
        self.assertEqual(name, expected_name)


if __name__ == "__main__":
    unittest.main()
