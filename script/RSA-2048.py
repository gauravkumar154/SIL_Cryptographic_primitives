from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # Import the padding module
from cryptography.hazmat.backends import default_backend

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
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

def encrypt(message, public_key):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.PKCS1v15()
    )
    return ciphertext

def decrypt(ciphertext, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    plaintext = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )
    return plaintext.decode('utf-8')

# Example usage
private_key, public_key = generate_key_pair()

message = "Hello, RSA encryption and decryption!"
ciphertext = encrypt(message, public_key)
decrypted_message = decrypt(ciphertext, private_key)

print("Original Message:", message)
print("Encrypted Message:", ciphertext)
print("Decrypted Message:", decrypted_message)
