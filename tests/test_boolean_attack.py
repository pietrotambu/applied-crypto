import unittest

from padding_oracle import attacks, crypto, services


class BooleanAttackTests(unittest.TestCase):
    def test_recover_plaintext_boolean(self) -> None:
        key = crypto.random_bytes(32)
        service = services.BasicOracleService(key)
        msg = b"this is a full task2 plaintext recovery test"
        ciphertext = service.encrypt(msg)

        recovered, _queries = attacks.recover_plaintext_boolean(ciphertext, service.padding_oracle)
        self.assertEqual(recovered, msg)


if __name__ == "__main__":
    unittest.main()
