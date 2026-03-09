import unittest

from padding_oracle import crypto, services


class ServicesTests(unittest.TestCase):
    def test_mac_then_encrypt_roundtrip(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)

        ct = service.encrypt(b"hello")
        self.assertTrue(service.check(ct))

    def test_mac_then_encrypt_tamper_fails(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)

        ct = service.encrypt(b"hello")
        tampered = bytearray(ct)
        tampered[-1] ^= 0x01
        self.assertFalse(service.check(bytes(tampered)))


if __name__ == "__main__":
    unittest.main()
