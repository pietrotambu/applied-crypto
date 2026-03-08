import unittest
import hashlib
import hmac

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

    def test_kb_to_bytes(self) -> None:
        self.assertEqual(utils.kb_to_bytes(1), 1024)
        self.assertEqual(utils.kb_to_bytes(0.5), 512)
        with self.assertRaises(ValueError):
            utils.kb_to_bytes(0)

    def test_proxy_command_args(self) -> None:
        args = utils.proxy_command_args(
            listen_addr="127.0.0.1:1111",
            target_addr="127.0.0.1:2222",
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

    def test_server_command_args_with_mac_options(self) -> None:
        args = utils.server_command_args(
            addr="127.0.0.1:4000",
            enc_key=b"\x01\x02",
            mac_key=b"\xaa\xbb",
            timing_work_factor=3,
            mac_alg="shake256",
            mac_tag_bytes=64,
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
                "--timing-work-factor",
                "3",
                "--mac-alg",
                "shake256",
                "--mac-tag-bytes",
                "64",
            ],
        )

    def test_expected_payload_helpers(self) -> None:
        msg = b"abc"
        mac_key = b"\x11\x22\x33"
        tag = hmac.new(mac_key, msg, hashlib.sha256).digest()
        expected = msg + tag
        padded = utils.expected_payload_padded(msg, mac_key)

        self.assertTrue(padded.startswith(expected))
        self.assertEqual(len(padded) % 16, 0)
        self.assertEqual(utils.expected_payload_block(msg, mac_key, 1), padded[:16])

    def test_random_message_from_kb(self) -> None:
        out = utils.random_message_from_kb(0.5)
        self.assertEqual(len(out), 512)
        self.assertTrue(out.decode("ascii").isalnum())


if __name__ == "__main__":
    unittest.main()
