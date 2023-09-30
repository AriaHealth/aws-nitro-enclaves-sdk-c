import unittest
from unittest.mock import MagicMock

from core import generate_mnemonic, shield_mnemonic
from utils import generate_keypair, asymmetric_decrypt


class TestCore(unittest.TestCase):
    def test_generate_mnemonic(self):
        # Mock the nitro_kms object
        nitro_kms = MagicMock()

        # Mock the kms_encrypt method to return a known value
        nitro_kms.kms_encrypt.return_value = {"CiphertextBlob": b"encrypted_mnemonic"}

        shielding_key = generate_keypair()

        # Call the function with known inputs
        result = generate_mnemonic(nitro_kms, "kms_key", shielding_key["public_key"])

        decrypted_mnemonic = asymmetric_decrypt(
            result["data"]["shielded_mnemonic"],
            result["data"]["nonce"],
            result["data"]["enclave_public_key"],
            shielding_key["private_key"],
        )

        # Check that the result is as expected
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["encrypted_mnemonic"], b"encrypted_mnemonic")
        self.assertEqual(len(decrypted_mnemonic.split()), 15)


if __name__ == "__main__":
    print("Running core.test.py...")
    unittest.main()
