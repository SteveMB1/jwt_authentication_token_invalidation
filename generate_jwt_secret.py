#!/usr/bin/env python3
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def main():
    # Base directory where JWT key folders live
    base_dir = os.path.join(os.path.dirname(__file__), "jwt_keys")
    os.makedirs(base_dir, exist_ok=True)

    # Find existing numeric subdirectories and pick the next integer as key ID
    existing_ids = []
    for name in os.listdir(base_dir):
        full_path = os.path.join(base_dir, name)
        if os.path.isdir(full_path) and name.isdigit():
            existing_ids.append(int(name))
    next_id = str(max(existing_ids) + 1) if existing_ids else "1"

    # Create the new subdirectory
    key_dir = os.path.join(base_dir, next_id)
    os.makedirs(key_dir, exist_ok=False)

    # Generate a new EC private key using P-521 (ES512)
    private_key = ec.generate_private_key(ec.SECP521R1())

    # Serialize and write the private key (PKCS#8, unencrypted)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(os.path.join(key_dir, "private_key.pem"), "wb") as f:
        f.write(priv_pem)

    # Derive and serialize the public key (SubjectPublicKeyInfo)
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(key_dir, "public_key.pem"), "wb") as f:
        f.write(pub_pem)

    print(f"✔ Generated ES512 key pair under: {key_dir}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
