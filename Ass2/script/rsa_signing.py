from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import secrets 
from pwn import xor

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Signature verification failed:", e)
        return False
    
def encrypt_rsa(plaintext, public_key):
    # Load the public key
   

    # Encrypt the plaintext
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    # Load the private key
  

    # Decrypt the ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext


# Example usage:
private_key, public_key = generate_rsa_keys()
nonce_tag_rsa = secrets.token_bytes(32)
# Message to be signed
message = b"Hello, RSA!"
cipher = encrypt_rsa(message,public_key)
print(cipher)
decro = decrypt_rsa(cipher,private_key)
print(decro,message)
# Signing the message
signature = sign_message(xor(message,nonce_tag_rsa), private_key)

# Verifying the signature
if verify_signature(public_key, signature, xor(message,nonce_tag_rsa)):
    print("Signature verification passed.")
else:
    print("Signature verification failed.")
