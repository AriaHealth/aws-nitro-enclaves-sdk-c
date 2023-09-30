"""Enclave NitroPepper application."""

import json
import socket

from kms import NitroKms
from enums.actions import ActionsEnum
from constants import ENCLAVE_PORT
from processes import (
    process_generate_hash_and_pepper,
    process_generate_mnemonic,
    process_validate_credentials,
    process_shield_mnemonic,
)


def main():
    """Run the nitro enclave application."""
    # Bind and listen on vsock.
    vsock = socket.socket(
        socket.AF_VSOCK, socket.SOCK_STREAM
    )  # pylint:disable=no-member
    vsock.bind((socket.VMADDR_CID_ANY, ENCLAVE_PORT))  # pylint:disable=no-member
    vsock.listen()

    # Initialize a KMS class
    nitro_kms = NitroKms()
    print("Listening...")

    while True:
        conn, _addr = vsock.accept()
        print("Received new connection")
        payload = conn.recv(4096)

        # Load the JSON data provided over vsock
        try:
            parent_app_data = json.loads(payload.decode())
            kms_credentials = parent_app_data["kms_credentials"]
            kms_region = parent_app_data["kms_region"]
        except Exception as exc:  # pylint:disable=broad-except
            msg = f"Exception ({type(exc)}) while loading JSON data: {str(exc)}"
            content = {
                "success": False,
                "error": msg,
            }

            conn.send(str.encode(json.dumps(content)))
            conn.close()
            continue

        nitro_kms.set_region(kms_region)
        nitro_kms.set_credentials(kms_credentials)

        if "action" in parent_app_data:
            if parent_app_data["action"] == ActionsEnum.GENERATE_HASH_AND_PEPPER:
                content = process_generate_hash_and_pepper(nitro_kms, parent_app_data)
            elif parent_app_data["action"] == ActionsEnum.VALIDATE_CREDENTIALS:
                content = process_validate_credentials(nitro_kms, parent_app_data)
            elif parent_app_data["action"] == ActionsEnum.GENERATE_MNEMONIC:
                content = process_generate_mnemonic(nitro_kms, parent_app_data)
            elif parent_app_data["action"] == ActionsEnum.SHIELD_MNEMONIC:
                content = process_shield_mnemonic(nitro_kms, parent_app_data)
            else:
                content = {
                    "success": False,
                    "error": f"Unknown action: {parent_app_data['action']}",
                }

        else:
            content = {
                "success": False,
                "error": "No action provided",
            }

        conn.send(str.encode(json.dumps(content)))
        conn.close()
        print("Closed connection")


# utils methods


if __name__ == "__main__":
    main()
