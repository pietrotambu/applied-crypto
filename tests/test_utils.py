import unittest

from padding_oracle import crypto, services, utils


class UtilsTests(unittest.TestCase):
    def test_parse_hex_aes_key_accepts_valid_lengths(self) -> None:
        self.assertEqual(len(utils.parse_hex_aes_key(("00" * 16))), 16)
        self.assertEqual(len(utils.parse_hex_aes_key(("00" * 24))), 24)
        self.assertEqual(len(utils.parse_hex_aes_key(("00" * 32))), 32)

    def test_parse_hex_aes_key_rejects_invalid_length(self) -> None:
        with self.assertRaises(ValueError):
            utils.parse_hex_aes_key("00" * 15)
        with self.assertRaises(ValueError):
            utils.parse_hex_aes_key("00" * 33)

    def test_parse_hex_mac_key_accepts_non_empty_lengths(self) -> None:
        self.assertEqual(len(utils.parse_hex_mac_key("00")), 1)
        self.assertEqual(len(utils.parse_hex_mac_key(("ab" * 64))), 64)

    def test_parse_hex_mac_key_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            utils.parse_hex_mac_key("")

    def test_kb_to_bytes(self) -> None:
        self.assertEqual(utils.kb_to_bytes(1), 1024)
        self.assertEqual(utils.kb_to_bytes(0.5), 512)
        with self.assertRaises(ValueError):
            utils.kb_to_bytes(0)

    def test_server_command_args(self) -> None:
        args = utils.server_command_args(
            addr="127.0.0.1:4000",
            enc_key=b"\x01\x02",
            mac_key=b"\xaa\xbb",
        )
        self.assertEqual(
            args,
            [
                "server",
                "--addr",
                "127.0.0.1:4000",
                "--enc-key",
                "0102",
                "--mac-key",
                "aabb",
            ],
        )

    def test_split_addr(self) -> None:
        host, port = utils.split_addr("127.0.0.1:4000")
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 4000)

    def test_expected_payload_helpers(self) -> None:
        msg = b"abc"
        mac_key = b"\x11\x22\x33"
        tag = services.compute_mac_tag(mac_key, msg)
        expected = msg + tag
        padded = utils.expected_payload_padded(msg, mac_key)

        self.assertTrue(padded.startswith(expected))
        self.assertEqual(len(padded) % 16, 0)
        self.assertEqual(utils.expected_payload_block(msg, mac_key, 1), padded[:16])

    def test_random_message_from_kb(self) -> None:
        out = utils.random_message_from_kb(0.5)
        self.assertEqual(len(out), 512)
        self.assertTrue(out.decode("ascii").isalnum())

    def test_choose_single_block_target_uses_last_when_not_full_padding(self) -> None:
        service = services.MacThenEncryptService(
            crypto.random_bytes(32),
            crypto.random_bytes(32),
        )
        msg = b"x" * 31
        ciphertext = service.encrypt(msg)
        num_blocks = len(ciphertext) // crypto.BLOCK_SIZE

        block_index, name = utils.choose_single_block_target(
            ciphertext,
            msg_len=len(msg),
        )
        self.assertEqual(block_index, num_blocks - 1)
        self.assertEqual(name, "last_payload_block")

    def test_choose_single_block_target_skips_full_padding_last_block(self) -> None:
        service = services.MacThenEncryptService(
            crypto.random_bytes(32),
            crypto.random_bytes(32),
        )
        msg = b"x" * 32
        ciphertext = service.encrypt(msg)
        num_blocks = len(ciphertext) // crypto.BLOCK_SIZE

        block_index, name = utils.choose_single_block_target(
            ciphertext,
            msg_len=len(msg),
        )
        self.assertEqual(block_index, num_blocks - 2)
        self.assertEqual(name, "second_last_payload_block")


if __name__ == "__main__":
    unittest.main()
