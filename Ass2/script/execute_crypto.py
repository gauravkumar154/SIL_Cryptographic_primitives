# Write your script here
from pwn import xor

#following for the aes 
import pyaes 
import os
import random

#importing the secret module of the python in order to generate the nonces 
import secrets
#these are for the RSA-2048 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # Import the padding module
from cryptography.hazmat.backends import default_backend
 
#these are for the sha3-256 
import hashlib 
import hmac
import os

#these are for the ecdsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

#importing the pycryptoplus for the AES-CMAC 
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def generate_keys_ecdsa():
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
def generate_ecdsa_signature(private_key, message):
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def generate_key_pair_rsa():
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

def encrypt_rsa(plaintext, public_key):
    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key,
        backend=None  # Use the default backend
    )

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
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None,  # No password for private key
        backend=None     # Use the default backend
    )

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

class ExecuteCrypto(object): # Do not change this 
    def generate_keys(self):
        """Generate keys"""

        random_integer = random.getrandbits(128)
        symmetric_key = random_integer.to_bytes(16, byteorder='big')

        private_key_sender_rsa, public_key_sender_rsa = generate_key_pair_rsa()
        private_key_receiver_rsa, public_key_receiver_rsa = generate_key_pair_rsa()
        private_key_sender_ecc , public_key_sender_ecc = generate_keys_ecdsa()

        print("Symmetric Key") # Do not change this
        print(symmetric_key) # Do not change this
        print("Sender's RSA Public Key") # Do not change this
        print(public_key_sender_rsa) # Do not change this
        print("Sender's RSA Private Key") # Do not change this
        print(private_key_sender_rsa) # Do not change this
        print("Receiver's RSA Public Key") # Do not change this
        print(public_key_receiver_rsa) # Do not change this
        print("Receiver's RSA Private Key") # Do not change this
        print(private_key_receiver_rsa) # Do not change this
        print("Sender's ECC Public Key") # Do not change this
        print(public_key_sender_ecc) # Do not change this
        print("Sender's ECC Private Key") # Do not change this
        print(private_key_sender_ecc) # Do not change this

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this

    def generate_nonces(self):
        """Generate nonces"""


      # Write your script here
        nonce_aes_cbc = secrets.token_bytes(16)
        nonce_aes_ctr = secrets.token_bytes(16)
        nonce_encrypt_rsa = secrets.token_bytes(32)  # RSA-2048 nonce size in bytes
        nonce_aes_cmac = secrets.token_bytes(16)
        nonce_hmac = secrets.token_bytes(16)
        nonce_tag_rsa = secrets.token_bytes(32)  # RSA-2048-SHA3-256 nonce size in bytes
        nonce_ecdsa = secrets.token_bytes(32)  # ECDSA nonce size in bytes
        nonce_aes_gcm = secrets.token_bytes(12)  # AES-128-GCM nonce size in bytes

  
      

        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("NOnce for RSA-2048") # Do not change this
        print(nonce_encrypt_rsa) # Do not change this
        print("Nonce for AES-128-CMAC") # Do not change this
        print(nonce_aes_cmac) # Do not change this
        print("Nonce for SHA3-256-HMAC") # Do not change this
        print(nonce_hmac) # Do not change this
        print("Nonce for RSA-2048-SHA3-256") # Do not change this
        print(nonce_tag_rsa) # Do not change this
        print("Nonce for ECDSA") # Do not change this
        print(nonce_ecdsa) # Do not change this
        print("Nonce for AES-128-GCM") # Do not change this
        print(nonce_aes_gcm) # Do not change this

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm # Do not change this

    def encrypt(self, algo, key, plaintext, nonce): # Do not change this
        """Encrypt the given plaintext"""

        # Write your script here


        if algo == 'AES-128-CBC-ENC': # Do not change this
            aes = pyaes.AESModeOfOperationCBC(key, iv=nonce)
            ciphertext = aes.encrypt(plaintext)
            # Write your script here

        elif algo == 'AES-128-CTR-ENC': # Do not change this
            print(len(nonce),len(key))
            aes = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(initial_value=int.from_bytes(nonce, byteorder='big')))
            ciphertext = aes.encrypt(plaintext)
            # Write your script here

        elif algo == 'RSA-2048-ENC': # Do not change this
            plaintext_nonced =bytes(x ^ y for x, y in zip(plaintext, nonce))
            ciphertext = encrypt_rsa(plaintext_nonced,key)

            # Write your script here

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this

        return ciphertext # Do not change this

    def decrypt(self, algo, key, ciphertext, nonce): # Do not change this
        """Decrypt the given ciphertext"""
        # Write your script here

        if algo=='AES-128-CBC-DEC': # Do not change this
            aes = pyaes.AESModeOfOperationCBC(key, iv=nonce )
            plaintext = aes.decrypt(ciphertext)
            # Write your script here

        elif algo == 'AES-128-CTR-DEC': # Do not change this
            aes = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(initial_value=int.from_bytes(nonce, byteorder='big')))
            plaintext = aes.encrypt(ciphertext)
            # Write your script here

        elif algo == 'RSA-2048-DEC': # Do not change this
            plaintext_nonced = decrypt_rsa(ciphertext,key)
            plaintext =bytes(x ^ y for x, y in zip(plaintext_nonced, nonce))
            
            # Write your script here

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        return plaintext # Do not change this

    def generate_auth_tag(self, algo, key, plaintext, nonce): # Do not change this
        """Generate the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-GEN': # Do not change this
            cobj = CMAC.new(key, ciphermod=AES)
            cobj.update(nonce)
            cobj.update(plaintext)
            cmac_tag = cobj.digest()
            auth_tag= cmac_tag

        # Write your script here

        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            """do we need to use the nonce , or if can directly xor it with the message bits , and do the procedure"""
            key = bytes(key, 'utf-8') if isinstance(key, str) else key
            message = xor(plaintext,nonce)
            auth_tag = hmac.new(key, message, hashlib.sha3_256).digest()
            # Write your script here

        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            
            message = xor(plaintext,nonce)
            auth_tag = encrypt_rsa(message,key)
            # Write your script here

        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
           plaintext_nonced = xor(plaintext,nonce)
           auth_tag = generate_ecdsa_signature(key,plaintext_nonced)
            
        
            # Write your script here

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return auth_tag # Do not change this

    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): # Do not change this
        """Verify the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-VRF': # Do not change this
            cobj = CMAC.new(key, ciphermod=AES)
            cobj.update(nonce)
            cobj.update(plaintext)
            cmac_tag = cobj.digest()
            auth_tag_valid = cmac_tag==auth_tag
            # Write your script here

        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            key = bytes(key, 'utf-8') if isinstance(key, str) else key
            message = xor(plaintext_message,nonce)
            auth_tag_valid = hmac.new(key, message, hashlib.sha3_256).digest() == auth_tag
            # Write your script here

        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            
            digest = xor(plaintext,nonce)
            auth_tag_valid = encrypt_rsa(digest,key) == auth_tag 
            # Write your script here

        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            plaintext_nonced = xor(plaintext,nonce)
            auth_tag_valid = generate_ecdsa_signature(key,plaintext_nonced) == auth_tag 
            # Write your script here

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return auth_tag_valid # Do not change this

    # def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
    #     """Encrypt and generate the authentication tag for the given plaintext"""

    #     # Write your script here

    #     if algo == 'AES-128-GCM-GEN': # Do not change this
    #         # Write your script here

    #     else:
    #         raise Exception("Unexpected algorithm") # Do not change this

    #     # Write your script here

    #     print("Algorithm") # Do not change this
    #     print(algo) # Do not change this
    #     print("Encryption Key") # Do not change this
    #     print(key_encrypt) # Do not change this
    #     print("Authentication Key") # Do not change this
    #     print(key_generate_auth) # Do not change this
    #     print("Plaintext") # Do not change this
    #     print(plaintext) # Do not change this
    #     print("Nonce") # Do not change this
    #     print(nonce) # Do not change this
    #     print("Ciphertext") # Do not change this
    #     print(ciphertext) # Do not change this
    #     print("Authentication Tag") # Do not change this
    #     print(auth_tag) # Do not change this

    #     return ciphertext, auth_tag # Do not change this

    # def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
    #     """Decrypt and verify the authentication tag for the given plaintext"""

    #     # Write your script here

    #     if algo == 'AES-128-GCM-VRF': # Do not change this
    #         # Write your script here

    #     else:
    #         raise Exception("Unexpected algorithm") # Do not change this

    #     # Write your script here

    #     print("Algorithm") # Do not change this
    #     print(algo) # Do not change this
    #     print("Decryption Key") # Do not change this
    #     print(key_decrypt) # Do not change this
    #     print("Authentication Key") # Do not change this
    #     print(key_verify_auth) # Do not change this
    #     print("Plaintext") # Do not change this
    #     print(plaintext) # Do not change this
    #     print("Nonce") # Do not change this
    #     print(nonce) # Do not change this
    #     print("Ciphertext") # Do not change this
    #     print(ciphertext) # Do not change this
    #     print("Authentication Tag") # Do not change this
    #     print(auth_tag) # Do not change this
    #     print("Authentication Tag Valid") # Do not change this
    #     print(auth_tag_valid) # Do not change this

    #     return plaintext, auth_tag_valid # Do not change this

if __name__ == '__main__': # Do not change this
    crypto_instance = ExecuteCrypto()

    # Generate keys
    symmetric_key, \
    public_key_sender_rsa, private_key_sender_rsa, \
    public_key_receiver_rsa, private_key_receiver_rsa, \
    public_key_sender_ecc, private_key_sender_ecc = crypto_instance.generate_keys()

    # Generate nonces
    nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
    nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm = crypto_instance.generate_nonces()

    # Encryption and Decryption Example
    plaintext_message = b"1234567890123456"
    auth_tag_hmac = crypto_instance.generate_auth_tag('algo_hmac', symmetric_key, plaintext_message, nonce_hmac)

    # Verification
    is_verified_hmac = crypto_instance.verify_auth_tag('algo_hmac', symmetric_key, plaintext_message, nonce_hmac, auth_tag_hmac)
    print(f"isverified :{is_verified_hmac}")

    # # AES-128-CBC Encryption and Decryption
    # encrypted_aes_cbc = crypto_instance.encrypt('AES-128-CBC-ENC', symmetric_key, plaintext_message, nonce_aes_cbc)
    # decrypted_aes_cbc = crypto_instance.decrypt('AES-128-CBC-DEC', symmetric_key, encrypted_aes_cbc, nonce_aes_cbc)

    # # AES-128-CTR Encryption and Decryption
    # encrypted_aes_ctr = crypto_instance.encrypt('AES-128-CTR-ENC', symmetric_key, plaintext_message, nonce_aes_ctr)
    # decrypted_aes_ctr = crypto_instance.decrypt('AES-128-CTR-DEC', symmetric_key, encrypted_aes_ctr, nonce_aes_ctr)

    # # RSA-2048 Encryption and Decryption
    # encrypted_rsa = crypto_instance.encrypt('RSA-2048-ENC', public_key_receiver_rsa, plaintext_message, nonce_encrypt_rsa)
    # decrypted_rsa = crypto_instance.decrypt('RSA-2048-DEC', private_key_receiver_rsa, encrypted_rsa, nonce_encrypt_rsa)

    # # Print results
    # print("\nAES-128-CBC:")
    # print("Plaintext:", plaintext_message)
    # print("Encrypted:", encrypted_aes_cbc)
    # print("Decrypted:", decrypted_aes_cbc)

    # print("\nAES-128-CTR:")
    # print("Plaintext:", plaintext_message)
    # print("Encrypted:", encrypted_aes_ctr)
    # print("Decrypted:", decrypted_aes_ctr)

    # print("\nRSA-2048:")
    # print("Plaintext:", plaintext_message)
    # print("Encrypted:", encrypted_rsa)
    # print("Decrypted:", decrypted_rsa)    
    

