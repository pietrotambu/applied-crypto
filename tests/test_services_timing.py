import unittest
from padding_oracle import crypto, services


class ServiceTimingTests(unittest.TestCase):
    def test_check_with_timing_success(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)

        ciphertext = service.encrypt(b"timing breakdown")
        ok, timing = service.check_with_timing(ciphertext)

        self.assertTrue(ok)
        self.assertGreater(timing.total_ns, 0)
        self.assertGreaterEqual(timing.decrypt_cbc_raw_ns, 0)
        self.assertGreaterEqual(timing.pkcs7_unpad_ns, 0)
        self.assertGreaterEqual(timing.hmac_sha256_ns, 0)
        self.assertGreaterEqual(timing.compare_digest_ns, 0)
        self.assertIn("total_ms", timing.as_ms())

    def test_check_with_timing_failure(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key)

        ciphertext = service.encrypt(b"timing breakdown")
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])

        ok, timing = service.check_with_timing(tampered)
        self.assertFalse(ok)
        self.assertGreater(timing.total_ns, 0)


if __name__ == "__main__":
    unittest.main()
