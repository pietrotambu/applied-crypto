import unittest

from padding_oracle import cli, crypto, services


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
        ciphertext = service.encrypt(b"hello world")

        block_index, name = cli._resolve_target_block_index(
            ciphertext=ciphertext,
            msg_len=len(b"hello world"),
            requested=1,
        )
        self.assertEqual(block_index, 1)
        self.assertEqual(name, "manual_payload_block")

    def test_resolve_target_block_index_rejects_out_of_range(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)
        ciphertext = service.encrypt(b"hello world")
        num_blocks = len(ciphertext) // crypto.BLOCK_SIZE

        with self.assertRaises(ValueError):
            cli._resolve_target_block_index(
                ciphertext=ciphertext,
                msg_len=len(b"hello world"),
                requested=0,
            )
        with self.assertRaises(ValueError):
            cli._resolve_target_block_index(
                ciphertext=ciphertext,
                msg_len=len(b"hello world"),
                requested=num_blocks,
            )


if __name__ == "__main__":
    unittest.main()
