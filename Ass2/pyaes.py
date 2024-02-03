import pyaes
import os
# aes = pyaes.AESModeOfOperationCTR(key_128)

plaintext = "a"
ans = b'W'
for i in range(2**16):
    # Convert the loop index to a 128-bit little-endian byte representation
    key_128 = i.to_bytes(16, byteorder='big')
    aes = pyaes.AESModeOfOperationCTR(key_128)
    ciphertext = aes.encrypt(plaintext)
    # decrypti = aes.decrypt(ciphertext)
    if (ans==ciphertext) :
        print(key_128)
        continue