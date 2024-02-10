from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes

def sign_message(private_key, message):
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )

    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA3_256())
    )

    return signature

def verify_signature(public_key, message, signature):
    public_key = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )

    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA3_256())
        )
        return True
    except Exception:
        return False

# Example usage:

# Generate keys
private_key, public_key = generate_keys()

# Your message to be signed
message = b"Hello, world!"

# Sign the message
signature = sign_message(private_key, message)

# Verify the signature
is_verified = verify_signature(public_key, message, signature)

print(f"Public Key:\n{public_key.decode()}")
print(f"Private Key:\n{private_key.decode()}")
print(f"Message: {message}")
print(f"Signature: {signature}")
print(f"Verification Result: {is_verified}")
