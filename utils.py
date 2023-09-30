import base64

from nacl.public import Box, PrivateKey, PublicKey
import nacl.utils


# methods


def base64_to_bytes(key):
    return base64.b64decode(key.encode("utf-8"))


def bytes_to_base64_string(key):
    return base64.b64encode(key).decode("utf-8")


def generate_keypair():
    keypair = PrivateKey.generate()
    private_key = bytes_to_base64_string(keypair.__bytes__())
    public_key = bytes_to_base64_string(keypair.public_key.__bytes__())

    return {
        "private_key": private_key,
        "public_key": public_key,
    }


def asymmetric_encrypt(secret, sender_private_key, receiver_public_key):
    """Encrypt a secret using an sender's private key and a receiver's public key."""
    sender_private_key = PrivateKey(base64_to_bytes(sender_private_key))
    receiver_public_key = PublicKey(base64_to_bytes(receiver_public_key))
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    sender_box = Box(sender_private_key, receiver_public_key)
    encrypted = sender_box.encrypt(bytes(secret, "utf-8"), nonce)

    return {
        "secret": bytes_to_base64_string(encrypted[Box.NONCE_SIZE :]),
        "nonce": bytes_to_base64_string(nonce),
    }


def asymmetric_decrypt(encrypted, nonce, sender_public_key, receiver_private_key):
    """Decrypt a secret using an sender's public key and a receiver's private key."""
    sender_public_key = PublicKey(base64_to_bytes(sender_public_key))
    receiver_private_key = PrivateKey(base64_to_bytes(receiver_private_key))

    receiver_box = Box(receiver_private_key, sender_public_key)
    decrypted = receiver_box.decrypt(
        base64_to_bytes(nonce) + base64_to_bytes(encrypted)
    )

    return decrypted.decode("utf-8")
