"""Enclave NitroPepper utils."""

import base64
import bcrypt


from bcrypt import _bcrypt
from mnemonic import Mnemonic

from constants import DEFAULT_MNEMONIC_LANGUAGE, DEFAULT_MNEMONIC_STRENGTH
from utils import asymmetric_encrypt, generate_keypair


def validate_credentials(
    nitro_kms, password: str, password_hash_b64: str, encrypted_pepper_b64: str
):
    """Decrypt the pepper, hash the given password with the pepper, and compare the results."""
    try:
        decrypted_pepper_bytes: bytes = nitro_kms.kms_decrypt(
            ciphertext_blob=encrypted_pepper_b64
        )
    except Exception as exc:  # pylint:disable=broad-except
        return {
            "success": False,
            "error": f"decrypt failed: {str(exc)}",
        }

    derived_key = bcrypt.hashpw(
        password=password.encode("utf-8"), salt=decrypted_pepper_bytes
    )

    ddb_password_hash_b64 = base64.b64encode(derived_key).decode("utf-8")
    return {
        "success": True,
        "credentials_valid": password_hash_b64 == ddb_password_hash_b64,
    }


def gensalt(nitro_kms, rounds: int = 12, prefix: bytes = b"2b") -> bytes:
    """
    Generate a salt for use in bcrypt.

    This function has been copied from
    https://github.com/pyca/bcrypt/blob/master/src/bcrypt/__init__.py. The
    only difference is replacing urandom with the NSM random function.
    """
    if prefix not in (b"2a", b"2b"):
        raise ValueError("Supported prefixes are b'2a' or b'2b'")

    if rounds < 4 or rounds > 31:
        raise ValueError("Invalid rounds")

    salt = nitro_kms.nsm_rand_func(16)
    output = _bcrypt.ffi.new("char[]", 30)  # pylint:disable=c-extension-no-member
    _bcrypt.lib.encode_base64(
        output, salt, len(salt)
    )  # pylint:disable=c-extension-no-member

    return (
        b"$"
        + prefix
        + b"$"
        + ("%2.2u" % rounds).encode("ascii")
        + b"$"
        + _bcrypt.ffi.string(output)  # pylint:disable=c-extension-no-member
    )


def generate_hash_and_pepper(nitro_kms, kms_key, password: str):
    """
    Generate a pepper and return a hashed password.

    The full process:
    1) Generate bcrypt salt
    2) Use that as a salt to hash the password
    3) Encrypt the byte string with KMS
    4) Return the hashed password and the encrypted salt (now a pepper)
    """
    try:
        bcrypt_salt_bytes = gensalt(nitro_kms)
    except Exception as exc:  # pylint:disable=broad-except
        return {
            "success": False,
            "error": f"generate_random failed: {str(exc)}",
        }

    # Use bcrypt.hashpw to hash the provided password (converted to bytes) using the
    # random bytes generated above as a salt. The result is also binary.
    derived_key = bcrypt.hashpw(
        password=password.encode("utf-8"),
        salt=bcrypt_salt_bytes,
    )

    # Encrypt the random byte string so we can return it to the caller.
    try:
        encrypt_response = nitro_kms.kms_encrypt(
            kms_key_id=kms_key, plaintext_bytes=bcrypt_salt_bytes
        )
    except Exception as exc:  # pylint:disable=broad-except
        return {
            "success": False,
            "error": f"encrypt failed: {str(exc)}",
        }

    password_hash_b64: str = base64.b64encode(derived_key).decode("utf-8")
    encrypted_pepper_b64: str = encrypt_response["CiphertextBlob"]

    return {
        "success": True,
        "data": {
            "password_hash_b64": password_hash_b64,
            "encrypted_pepper_b64": encrypted_pepper_b64,
        },
    }


def generate_mnemonic(nitro_kms, kms_key: str, shielding_key: str):
    """Generate BIP39 mnemonic phrase securely.

    The full process:
    1. Consider shielding key as a requester public key (PB)
    2. Verify that the shielding key is valid
    3. Generate NaCl key pair and take the private key (PR)
    4. Generate the mnemonic phrase
    5. Encrypt the mnemonic phrase using the NaCl box utilizing PB and PR
    6. Store the kms encrypted mnemonic phrase in the database
    """
    try:
        mnemo = Mnemonic(DEFAULT_MNEMONIC_LANGUAGE)
        mnemonic = mnemo.generate(DEFAULT_MNEMONIC_STRENGTH)

        enclave_keypair = generate_keypair()
        enclave_private_key = enclave_keypair["private_key"]
        enclave_public_key = enclave_keypair["public_key"]

        shielded = asymmetric_encrypt(mnemonic, enclave_private_key, shielding_key)

        encrypt_response = nitro_kms.kms_encrypt(
            kms_key_id=kms_key,
            plaintext_bytes=mnemonic.encode("utf-8"),
        )
        encrypted_mnemonic: str = encrypt_response["CiphertextBlob"]

        return {
            "success": True,
            "data": {
                "shielded_mnemonic": shielded["secret"],
                "nonce": shielded["nonce"],
                "encrypted_mnemonic": encrypted_mnemonic,
                "enclave_public_key": enclave_public_key,
            },
        }
    except Exception as exc:  # pylint:disable=broad-except
        return {
            "success": False,
            "error": f"mnemonic generation failed: {str(exc)}",
        }


def shield_mnemonic(nitro_kms, nitro_encrypted_mnemonic: str, shielding_key: str):
    """Shield BIP39 mnemonic phrase securely."""
    try:
        decrypted_mnemonic: bytes = nitro_kms.kms_decrypt(
            ciphertext_blob=nitro_encrypted_mnemonic
        )

        enclave_keypair = generate_keypair()
        enclave_private_key = enclave_keypair["private_key"]
        enclave_public_key = enclave_keypair["public_key"]

        shielded = asymmetric_encrypt(
            decrypted_mnemonic.decode("utf-8"), enclave_private_key, shielding_key
        )

        return {
            "success": True,
            "data": {
                "shielded_mnemonic": shielded["secret"],
                "nonce": shielded["nonce"],
                "enclave_public_key": enclave_public_key,
            },
        }
    except Exception as exc:  # pylint:disable=broad-except
        return {
            "success": False,
            "error": f"mnemonic shielding failed: {str(exc)}",
        }
