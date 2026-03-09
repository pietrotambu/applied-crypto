import unittest

from padding_oracle import attacks, crypto, services, utils


class BooleanAttackTests(unittest.TestCase):
    def test_recover_plaintext_boolean(self) -> None:
        key = crypto.random_bytes(32)
        service = services.BasicOracleService(key)
        msg = utils.random_message_from_kb(0.05)
        ciphertext = service.encrypt(msg)

        recovered, queries = attacks.recover_plaintext_boolean(ciphertext, service.padding_oracle)
        self.assertEqual(recovered, msg)
        self.assertGreater(queries, 0)


if __name__ == "__main__":
    unittest.main()
