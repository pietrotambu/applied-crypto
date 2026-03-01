import unittest

from padding_oracle import utils


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

    def test_proxy_command_args(self) -> None:
        args = utils.proxy_command_args(
            listen_addr="127.0.0.1:1111",
            target_addr="127.0.0.1:2222",
            base_delay_ms=0.0,
            jitter_ms=0.01,
        )
        self.assertEqual(
            args,
            [
                "proxy",
                "--listen",
                "127.0.0.1:1111",
                "--target",
                "127.0.0.1:2222",
                "--base-delay-ms",
                "0.0",
                "--jitter-ms",
                "0.01",
            ],
        )

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


if __name__ == "__main__":
    unittest.main()
