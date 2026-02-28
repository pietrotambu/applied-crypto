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


if __name__ == "__main__":
    unittest.main()
