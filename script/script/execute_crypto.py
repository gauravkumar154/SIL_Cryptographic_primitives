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
from cryptography.hazmat.primitives.asymmetric import rsa  # Import the padding 
from cryptography.hazmat.primitives.asymmetric import padding  as padding # Import the padding module 

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding2  #for rsa ,OAEP
from cryptography.exceptions import InvalidTag

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


def generate_ecdsa_keys():
    private_key = ec.generate_private_key(
        ec.SECP256R1(), 
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_ecdsa_signature(private_key, message):
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_ecdsa_signature(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        return False


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
    
# def encrypt_rsa(plaintext, public_key):
#     # Load the public key
   

#     # Encrypt the plaintext
#     ciphertext = public_key.encrypt(
#         plaintext,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )

#     return ciphertext
def encrypt_rsa(plaintext, public_key):
    # Encrypt the plaintext
    ciphertext = public_key.encrypt(
        plaintext,
        padding.PKCS1v15()
    )

    return ciphertext



#     return plaintext
def decrypt_rsa(ciphertext, private_key):
    # Decrypt the ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )

    return plaintext

def encrypt_and_digest_aes_gcm(nonce ,key, plaintext, associated_data=b""):
    # Generate a random IV (Initialization Vector)
    iv = nonce  # 96 bits IV for GCM mode
    
    # Create a GCM cipher object
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    
    # Create an encryptor object
    encryptor = cipher.encryptor()
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag
    
    return iv, ciphertext, tag
def decrypt_and_verify_aes_gcm(key, iv, ciphertext, tag, associated_data=b""):
    # Create a GCM cipher object with the same IV and tag
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    
    # Create a decryptor object
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
    except InvalidTag:
        # Invalid authentication tag
        plaintext = b"Invalid authentication tag! Decryption failed."

    return plaintext  


class ExecuteCrypto(object): # Do not change this 
    def generate_keys(self):
        """Generate keys"""

        random_integer = random.getrandbits(128)
        symmetric_key = random_integer.to_bytes(16, byteorder='big')

        private_key_sender_rsa, public_key_sender_rsa = generate_rsa_keys()
        private_key_receiver_rsa, public_key_receiver_rsa = generate_rsa_keys()
        private_key_sender_ecc , public_key_sender_ecc = generate_ecdsa_keys()

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
            plaintext=plaintext.encode()
            cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad the plaintext to match the block size of AES
            padder = padding2.PKCS7(algorithms.AES.block_size).padder()
            padded_plaintext = padder.update(plaintext) + padder.finalize()
            
            # Encrypt the padded plaintext
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
            
            return ciphertext
            # Write your script here

        elif algo == 'AES-128-CTR-ENC': # Do not change this
            print(len(nonce),len(key))
            aes = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(initial_value=int.from_bytes(nonce, byteorder='big')))
            ciphertext = aes.encrypt(plaintext)
            # Write your script here

        elif algo == 'RSA-2048-ENC': # Do not change this
            print((plaintext))
           
            # plaintext_nonced = xor(plaintext,nonce)
            # print((plaintext_nonced))
            ciphertext = encrypt_rsa(plaintext,key)

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
            cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())
    
            # Create a decryptor object
            decryptor = cipher.decryptor()
            
            # Decrypt the ciphertext
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad the plaintext
            unpadder = padding2.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            plaintext = plaintext.decode("utf-8")
            # Write your script here

        elif algo == 'AES-128-CTR-DEC': # Do not change this
            aes = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(initial_value=int.from_bytes(nonce, byteorder='big')))
            plaintext = aes.encrypt(ciphertext).decode("utf-8")
            # Write your script here

        elif algo == 'RSA-2048-DEC': # Do not change this
            plaintext = decrypt_rsa(ciphertext,key)
            

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
            plaintext = plaintext.encode()
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
            
            auth_tag = sign_message(xor(plaintext,nonce), key)

            # Write your script here

        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
           auth_tag = generate_ecdsa_signature(key,xor(plaintext,nonce))
            
        
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
            plaintext=plaintext.encode()
            cobj = CMAC.new(key, ciphermod=AES)
            cobj.update(nonce)
            cobj.update(plaintext)
            cmac_tag = cobj.digest()
            auth_tag_valid = cmac_tag==auth_tag
            # Write your script here

        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            key = bytes(key, 'utf-8') if isinstance(key, str) else key
            message = xor(plaintext,nonce)
            auth_tag_valid = hmac.new(key, message, hashlib.sha3_256).digest() == auth_tag
            # Write your script here

        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            auth_tag_valid = verify_signature(key, auth_tag, xor(plaintext,nonce)) # digest = xor(plaintext,nonce)
            
            # Write your script here

        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            auth_tag_valid = verify_ecdsa_signature(key,auth_tag,xor(plaintext,nonce))
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

    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
        """Encrypt and generate the authentication tag for the given plaintext"""

        # Write your script here

        if algo == 'AES-128-GCM-GEN': # Do not change this
            plaintext= plaintext.encode()
            nonce ,ciphertext,auth_tag = encrypt_and_digest_aes_gcm(nonce,key_encrypt,plaintext)
            #generate the GCM tag 
            print(len(ciphertext))
            print(len(auth_tag))
            # Write your script here


        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key_encrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_generate_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return ciphertext, auth_tag # Do not change this

    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
        """Decrypt and verify the authentication tag for the given plaintext"""

        # Write your script here

        if algo == 'AES-128-GCM-VRF': # Do not change this
            # Write your script here
            plaintext = decrypt_and_verify_aes_gcm(key_decrypt,nonce,ciphertext,auth_tag)
            if(plaintext == b"Invalid authentication tag! Decryption failed.") :
                auth_tag_valid = False 
            else :
                auth_tag_valid = True
            plaintext=plaintext.decode("utf-8")

            

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key_decrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_verify_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return plaintext, auth_tag_valid # Do not change this

if __name__ == '__main__': # Do not change this
    crypto_instance = ExecuteCrypto()

   
