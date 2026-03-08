import unittest

from padding_oracle import crypto, services


class ServicesTests(unittest.TestCase):
    def test_mac_then_encrypt_roundtrip_sha256(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(enc_key, mac_key, mac_alg="sha256")

        ct = service.encrypt(b"hello")
        self.assertTrue(service.check(ct))

    def test_mac_then_encrypt_roundtrip_shake256(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service = services.MacThenEncryptService(
            enc_key,
            mac_key,
            mac_alg="shake256",
            mac_tag_bytes=64,
        )

        ct = service.encrypt(b"hello")
        self.assertTrue(service.check(ct))

    def test_shake256_tag_mismatch_fails(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        service_a = services.MacThenEncryptService(enc_key, mac_key, mac_alg="shake256", mac_tag_bytes=32)
        service_b = services.MacThenEncryptService(enc_key, mac_key, mac_alg="shake256", mac_tag_bytes=64)

        ct = service_a.encrypt(b"hello")
        self.assertFalse(service_b.check(ct))

    def test_sha256_rejects_non_default_tag_size(self) -> None:
        enc_key = crypto.random_bytes(32)
        mac_key = crypto.random_bytes(32)
        with self.assertRaises(ValueError):
            services.MacThenEncryptService(
                enc_key,
                mac_key,
                mac_alg="sha256",
                mac_tag_bytes=64,
            )


if __name__ == "__main__":
    unittest.main()
