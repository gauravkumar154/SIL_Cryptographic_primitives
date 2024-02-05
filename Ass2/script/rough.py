import pyaes
import random 
import secrets 

random_integer = random.getrandbits(128)
key = random_integer.to_bytes(16, byteorder='big')
iv = secrets.token_bytes(16)  # Use IV instead of nonce
text = b"0123456789123456"

aes = pyaes.AESModeOfOperationCBC(key, iv=iv)  # Use IV here

# Encrypt
ciphertext = aes.encrypt(text)

# Decrypt
aes_decrypt = pyaes.AESModeOfOperationCBC(key, iv=iv)  # Use the same IV for decryption
decrypted_text = aes_decrypt.decrypt(ciphertext)

print(f'Plaintext: {decrypted_text}')
