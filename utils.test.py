import unittest


from utils import (
    asymmetric_encrypt,
    asymmetric_decrypt,
    generate_keypair,
    bytes_to_base64_string,
    base64_to_bytes,
)


class TestUtils(unittest.TestCase):
    def test_base64_to_bytes(self):
        # test that base64_to_bytes returns a bytes from a base64 string
        key = "aGVsbG8="
        self.assertTrue(base64_to_bytes(key) == b"hello")

    def test_bytes_to_base64_string(self):
        # test that bytes_to_base64_string returns a base64 string from a bytes
        key = b"hello"
        self.assertTrue(bytes_to_base64_string(key) == "aGVsbG8=")

    def test_generate_keypair(self):
        # test that generate_keypair returns a dict with a private key and a public key
        keypair = generate_keypair()

        self.assertTrue("private_key" in keypair)
        self.assertTrue("public_key" in keypair)

    def test_asymmetric_encrypt_and_decrypt(self):
        # test that asymmetric_encrypt and asymmetric_decrypt are inverses
        sender_keypair = generate_keypair()
        receiver_keypair = generate_keypair()

        sender_private_key = sender_keypair["private_key"]
        receiver_private_key = receiver_keypair["private_key"]

        sender_public_key = sender_keypair["public_key"]
        receiver_public_key = receiver_keypair["public_key"]

        message = "hello"

        encrypted = asymmetric_encrypt(
            message,
            sender_private_key,
            receiver_public_key,
        )
        decrypted = asymmetric_decrypt(
            encrypted["secret"],
            encrypted["nonce"],
            sender_public_key,
            receiver_private_key,
        )

        self.assertTrue(decrypted == message)

    def test_pynacl_with_tweetnacl_js_generated_keypair(self):
        # test that the encryption and decryption is compatible with tweetnacl-js

        # tweetnacl-js generates a random keypair for each message
        sender_private_key = "c8a0Uu9IUn0FlBXHMa1ImAJ152ds9qDKOwAu5YQ3Hws="
        sender_public_key = "GUFLN/08jZ6u8l91mAW7YCS2QhCLyvoL9enmfGU9Fjk="

        receiver_private_key = "EVKDG+8f+Crvx93ZXrKduVl53hVELnhisPTJricvx7w="
        receiver_public_key = "HHUip/1kSC6aZ4cKnC9xYIl0ocsZ1epjEO6izyFljFc="

        message = "hello"

        encrypted = asymmetric_encrypt(
            message,
            sender_private_key,
            receiver_public_key,
        )
        decrypted = asymmetric_decrypt(
            encrypted["secret"],
            encrypted["nonce"],
            sender_public_key,
            receiver_private_key,
        )

        self.assertTrue(decrypted == message)

    def test_pynacl_with_tweetnacl_js_generated_keypair_and_ciphertext(self):
        # test that the encryption and decryption is compatible with tweetnacl-js

        # tweetnacl-js generates a random keypair for each message
        sender_private_key = "KjnPBJxMBErkj5ZV17wZ6paBCnUkoRZU3I++9g3B0Lo="
        sender_public_key = "7zESVDQrIOGyv9sxZf9UNMG/F19QW7GrC2P5MUV/9yU="

        receiver_private_key = "cqvlTW1NcNAn5Ck3KXQSCqIFPhzgEX2UOkQgSr3H7Bw="
        receiver_public_key = "Za673h9IihJYCUjUh40ricgXbOE90u1QtlfVwiiGsGU="

        message = "test"

        encrypted = {
            "secret": "C6qUIbJva/NmLib3p7F2rCp2gxI=",
            "nonce": "sSiPdV7pdQ8WfaQrsfhEBPu/aMmbKLnX",
        }

        decrypted = asymmetric_decrypt(
            encrypted["secret"],
            encrypted["nonce"],
            sender_public_key,
            receiver_private_key,
        )

        self.assertTrue(decrypted == message)


if __name__ == "__main__":
    print("Running utils.test.py...")
    unittest.main()
