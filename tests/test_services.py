import unittest

from padding_oracle import crypto, services, timing_stats, utils


class ServicesTests(unittest.TestCase):
    def test_mac_then_encrypt_roundtrip(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)
        msg = utils.random_message_from_kb(0.02)

        ct = service.encrypt(msg)
        self.assertTrue(service.check(ct))
        padded_payload = crypto.decrypt_cbc_raw(enc_key, ct)
        self.assertEqual(padded_payload, utils.expected_payload_padded(msg, mac_key))

    def test_mac_then_encrypt_tamper_fails(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)
        msg = b"message with mac"

        ct = service.encrypt(msg)
        tampered = timing_stats._tamper_mac(ct)
        self.assertFalse(service.check(tampered))


if __name__ == "__main__":
    unittest.main()
