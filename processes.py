"""Enclave NitroPepper processes."""


from core import (
    shield_mnemonic,
    validate_credentials,
    generate_hash_and_pepper,
    generate_mnemonic,
)


def process_validate_credentials(nitro_kms, parent_app_data):
    """Process a validate_credentials command."""
    # Validate all required keys are present
    mandatory_keys = ["kms_key", "password", "password_hash", "encrypted_pepper"]
    for mandatory_key in mandatory_keys:
        if mandatory_key not in parent_app_data:
            return {
                "success": False,
                "error": f"Mandatory key {mandatory_key} is missing",
            }

    # Execute the actual call
    return validate_credentials(
        nitro_kms,
        parent_app_data["password"],
        parent_app_data["password_hash"],
        parent_app_data["encrypted_pepper"],
    )


def process_generate_hash_and_pepper(nitro_kms, parent_app_data):
    """Process a generate_hash_and_pepper command."""
    # Validate all required keys are present
    mandatory_keys = ["password", "kms_key"]
    for mandatory_key in mandatory_keys:
        if mandatory_key not in parent_app_data:
            return {
                "success": False,
                "error": f"Mandatory key {mandatory_key} is missing",
            }
    # Execute the actual call
    return generate_hash_and_pepper(
        nitro_kms,
        parent_app_data["kms_key"],
        parent_app_data["password"],
    )


def process_generate_mnemonic(nitro_kms, parent_app_data):
    """Process a mnemonic generation that is secured using shielding key."""
    # Validate all required keys are present
    mandatory_keys = ["shielding_key", "kms_key"]
    for mandatory_key in mandatory_keys:
        if mandatory_key not in parent_app_data:
            return {
                "success": False,
                "error": f"Mandatory key {mandatory_key} is missing",
            }
    # Execute the actual call
    return generate_mnemonic(
        nitro_kms,
        parent_app_data["kms_key"],
        parent_app_data["shielding_key"],
    )


def process_shield_mnemonic(nitro_kms, parent_app_data):
    """Process a mnemonic shielding for data retreivals."""
    # Validate all required keys are present
    mandatory_keys = ["nitro_encrypted_mnemonic", "shielding_key", "kms_key"]
    for mandatory_key in mandatory_keys:
        if mandatory_key not in parent_app_data:
            return {
                "success": False,
                "error": f"Mandatory key {mandatory_key} is missing",
            }

    # Execute the actual call
    return shield_mnemonic(
        nitro_kms,
        parent_app_data["nitro_encrypted_mnemonic"],
        parent_app_data["shielding_key"],
    )
