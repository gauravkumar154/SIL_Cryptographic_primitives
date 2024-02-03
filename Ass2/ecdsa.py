from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def generate_ec_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def sign_message(message, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    signature = private_key.sign(
        message.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(message, signature, public_key):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Example usage
private_key, public_key = generate_ec_key_pair()

message = "Hello, ECDSA!"
signature = sign_message(message, private_key)
verification_result = verify_signature(message, signature, public_key)

print("Original Message:", message)
print("Signature:", signature)
print("Signature Verification Result:", verification_result)
