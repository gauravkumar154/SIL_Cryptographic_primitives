import time
import execute_crypto
import string
import random
import matplotlib.pyplot as plt
# Example code for calculating time for each operation
crypto_instance = execute_crypto.ExecuteCrypto()
symmetric_key, \
public_key_sender_rsa, private_key_sender_rsa, \
public_key_receiver_rsa, private_key_receiver_rsa, \
public_key_sender_ecc, private_key_sender_ecc = crypto_instance.generate_keys()


# Generate nonces
nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm = crypto_instance.generate_nonces()

# Encryption and Decryption Example


def generate_plain_text(size):
    return ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=size))

test_cases = []
sizes =[]
for i in range (50):
    sizes.append((i+1)*100)

for size in sizes:
    plaintext = generate_plain_text(size)
    test_cases.append(plaintext)



auth_tag_cmac_list = []
verify_cmac_tag_list = []
for i in range(len(test_cases)):
    start_time = time.time()
    auth_tag_cmac = crypto_instance.generate_auth_tag('AES-128-CMAC-GEN', symmetric_key, test_cases[i], nonce_aes_cmac)
    end_time = time.time()
    auth_tag_cmac_list.append((end_time - start_time)*1000)
    start_time = time.time()
    is_verified_cmac = crypto_instance.verify_auth_tag('AES-128-CMAC-VRF', symmetric_key, test_cases[i], nonce_aes_cmac, auth_tag_cmac)
    end_time = time.time()
    verify_cmac_tag_list.append((end_time - start_time)*1000)

plt.figure(figsize=(10, 6))
plt.plot(sizes, auth_tag_cmac_list, label='Auth Tag Generation Time (AES-128-CMAC-GEN)')
plt.plot(sizes, verify_cmac_tag_list, label='Auth Tag Verification Time (AES-128-CMAC-VRF)')
plt.xlabel('Size of Plaintext Message (bytes)')
plt.ylabel('Time (ms)')
plt.title('Time Taken for Authentication Tag Generation and Verification vs. Size of Plaintext Message')
plt.legend()
plt.grid(True)
# plt.show()
# # # Verification
# print(f"isverified :{is_verified_cmac}")

auth_tag_cmac_list = []
verify_cmac_tag_list = []
for i in range(len(test_cases)):
    start_time = time.time()
    auth_tag_hmac = crypto_instance.generate_auth_tag('SHA3-256-HMAC-GEN', symmetric_key, test_cases[i], nonce_hmac)
    end_time = time.time()
    auth_tag_cmac_list.append((end_time - start_time)*1000)
    start_time = time.time()
    is_verified_hmac = crypto_instance.verify_auth_tag('SHA3-256-HMAC-VRF', symmetric_key, test_cases[i], nonce_hmac, auth_tag_hmac)
    end_time = time.time()
    verify_cmac_tag_list.append((end_time - start_time)*1000)

plt.figure(figsize=(10, 6))
plt.plot(sizes, auth_tag_cmac_list, label='Auth Tag Generation Time (SHA3-256-HMAC-GEN)')
plt.plot(sizes, verify_cmac_tag_list, label='Auth Tag Verification Time (SHA3-256-HMAC-VRF)')
plt.xlabel('Size of Plaintext Message (bytes)')
plt.ylabel('Time (ms)')
plt.title('Time Taken for Authentication Tag Generation and Verification vs. Size of Plaintext Message')
plt.legend()
plt.grid(True)
# plt.show()
# auth_tag_hmac = crypto_instance.generate_auth_tag('SHA3-256-HMAC-GEN', symmetric_key, plaintext_message, nonce_hmac)
# is_verified_hmac = crypto_instance.verify_auth_tag('SHA3-256-HMAC-VRF', symmetric_key, plaintext_message, nonce_hmac, auth_tag_hmac)

# # # # Verification
# # print(f"isverified :{is_verified_hmac}")
auth_tag_cmac_list = []
verify_cmac_tag_list = []
for i in range(len(test_cases)):
    start_time = time.time()
    auth_rsa_sha = crypto_instance.generate_auth_tag('RSA-2048-SHA3-256-SIG-GEN', private_key_sender_rsa, test_cases[i], nonce_tag_rsa)
    end_time = time.time()
    auth_tag_cmac_list.append((end_time - start_time)*1000)
    start_time = time.time()
    is_verified_rsa_sha = crypto_instance.verify_auth_tag('RSA-2048-SHA3-256-SIG-VRF', public_key_sender_rsa, test_cases[i], nonce_tag_rsa, auth_rsa_sha)
    end_time = time.time()
    verify_cmac_tag_list.append((end_time - start_time)*1000)

plt.figure(figsize=(10, 6))
plt.plot(sizes, auth_tag_cmac_list, label='Auth Tag Generation Time (RSA-2048-SHA3-256-SIG-GEN)')
plt.plot(sizes, verify_cmac_tag_list, label='Auth Tag Verification Time (RSA-2048-SHA3-256-SIG-VRF)')
plt.xlabel('Size of Plaintext Message (bytes)')
plt.ylabel('Time (ms)')
plt.title('Time Taken for Authentication Tag Generation and Verification vs. Size of Plaintext Message')
plt.legend()
plt.grid(True)
# plt.show()
# auth_rsa_sha = crypto_instance.generate_auth_tag('RSA-2048-SHA3-256-SIG-GEN', private_key_sender_rsa, plaintext_message, nonce_tag_rsa)
# is_verified_rsa_sha = crypto_instance.verify_auth_tag('RSA-2048-SHA3-256-SIG-VRF', public_key_sender_rsa, plaintext_message, nonce_tag_rsa, auth_rsa_sha)

# # # # Verification
# # print(f"isverified :{is_verified_rsa_sha}")
auth_tag_cmac_list = []
verify_cmac_tag_list = []
for i in range(len(test_cases)):
    start_time = time.time()
    auth_ecdsa_sha = crypto_instance.generate_auth_tag('ECDSA-256-SHA3-256-SIG-GEN', private_key_sender_ecc, test_cases[i], nonce_ecdsa)
    end_time = time.time()
    auth_tag_cmac_list.append((end_time - start_time)*1000)
    start_time = time.time()
    is_verified_ecdsa_sha = crypto_instance.verify_auth_tag('ECDSA-256-SHA3-256-SIG-VRF', public_key_sender_ecc, test_cases[i], nonce_ecdsa, auth_ecdsa_sha)
    end_time = time.time()
    verify_cmac_tag_list.append((end_time - start_time)*1000)

plt.figure(figsize=(10, 6))
plt.plot(sizes, auth_tag_cmac_list, label='Auth Tag Generation Time (ECDSA-256-SHA3-256-SIG-GEN)')
plt.plot(sizes, verify_cmac_tag_list, label='Auth Tag Verification Time (ECDSA-256-SHA3-256-SIG-VRF)')
plt.xlabel('Size of Plaintext Message (bytes)')
plt.ylabel('Time (ms)')
plt.title('Time Taken for Authentication Tag Generation and Verification vs. Size of Plaintext Message')
plt.legend()
plt.grid(True)
# plt.show()
# auth_ecdsa_sha = crypto_instance.generate_auth_tag('ECDSA-256-SHA3-256-SIG-GEN', private_key_sender_ecc, plaintext_message, nonce_ecdsa)
# is_verified_ecdsa_sha = crypto_instance.verify_auth_tag('ECDSA-256-SHA3-256-SIG-VRF', public_key_sender_ecc, plaintext_message, nonce_ecdsa, auth_ecdsa_sha)

# # # # Verification
# # print(f"isverified :{is_verified_ecdsa_sha}")


# # AES-128-CBC Encryption and Decryption
auth_tag_cmac_list = []
verify_cmac_tag_list = []
for i in range(len(test_cases)):
    start_time = time.time()
    ciphertext_aes_cbc = crypto_instance.encrypt('AES-128-CBC-ENC', symmetric_key, test_cases[i], nonce_aes_cbc)
    end_time = time.time()
    auth_tag_cmac_list.append((end_time - start_time)*1000)
    start_time = time.time()
    decrypted_aes_cbc = crypto_instance.decrypt('AES-128-CBC-DEC', symmetric_key, ciphertext_aes_cbc, nonce_aes_cbc)
    end_time = time.time()
    verify_cmac_tag_list.append((end_time - start_time)*1000)

plt.figure(figsize=(10, 6))
plt.plot(sizes, auth_tag_cmac_list, label='plaintext encryption Time (AES-128-CBC-ENC)')
plt.plot(sizes, verify_cmac_tag_list, label='ciphertext decryption Time (AES-128-CBC-DEC)')
plt.xlabel('Size of Plaintext Message (bytes)')
plt.ylabel('Time (ms)')
plt.title('Time Taken for encryption and decryption vs. Size of Plaintext Message')
plt.legend()
plt.grid(True)
# plt.show()
# ciphertext_aes_cbc = crypto_instance.encrypt('AES-128-CBC-ENC', symmetric_key, plaintext_message, nonce_aes_cbc)
# decrypted_aes_cbc = crypto_instance.decrypt('AES-128-CBC-DEC', symmetric_key, ciphertext_aes_cbc, nonce_aes_cbc)

# # AES-128-CTR Encryption and Decryption
auth_tag_cmac_list = []
verify_cmac_tag_list = []
for i in range(len(test_cases)):
    start_time = time.time()
    encrypted_aes_ctr = crypto_instance.encrypt('AES-128-CTR-ENC', symmetric_key, test_cases[i], nonce_aes_ctr)
    end_time = time.time()
    auth_tag_cmac_list.append((end_time - start_time)*1000)
    start_time = time.time()
    decrypted_aes_ctr = crypto_instance.decrypt('AES-128-CTR-DEC', symmetric_key, encrypted_aes_ctr, nonce_aes_ctr)
    end_time = time.time()
    verify_cmac_tag_list.append((end_time - start_time)*1000)

plt.figure(figsize=(10, 6))
plt.plot(sizes, auth_tag_cmac_list, label='plaintext encryption Time (AES-128-CTR-ENC)')
plt.plot(sizes, verify_cmac_tag_list, label='ciphertext decryption Time (AES-128-CTR-DEC')
plt.xlabel('Size of Plaintext Message (bytes)')
plt.ylabel('Time (ms)')
plt.title('Time Taken for encryption and decryption vs. Size of Plaintext Message')
plt.legend()
plt.grid(True)
plt.show()
# encrypted_aes_ctr = crypto_instance.encrypt('AES-128-CTR-ENC', symmetric_key, plaintext_message, nonce_aes_ctr)
# decrypted_aes_ctr = crypto_instance.decrypt('AES-128-CTR-DEC', symmetric_key, encrypted_aes_ctr, nonce_aes_ctr)

# # RSA-2048 Encryption and Decryption

# encrypted_rsa = crypto_instance.encrypt('RSA-2048-ENC', public_key_receiver_rsa, plaintext_message, nonce_encrypt_rsa)
# decrypted_rsa = crypto_instance.decrypt('RSA-2048-DEC', private_key_receiver_rsa, encrypted_rsa, nonce_encrypt_rsa)

# #Encrypt and authenticate AES-GCM 
auth_tag_cmac_list = []
verify_cmac_tag_list = []
for i in range(len(test_cases)):
    start_time = time.time()
    cipher , tag = crypto_instance.encrypt_generate_auth("AES-128-GCM-GEN",symmetric_key,symmetric_key,test_cases[i],nonce_aes_gcm)
    end_time = time.time()
    auth_tag_cmac_list.append((end_time - start_time)*1000)
    start_time = time.time()
    plain , valid = crypto_instance.decrypt_verify_auth("AES-128-GCM-VRF",symmetric_key,symmetric_key,cipher,nonce_aes_gcm,tag)
    end_time = time.time()
    verify_cmac_tag_list.append((end_time - start_time)*1000)

plt.figure(figsize=(10, 6))
plt.plot(sizes, auth_tag_cmac_list, label='plaintext encryption and tag generation Time (AES-128-GCM-GEN)')
plt.plot(sizes, verify_cmac_tag_list, label='ciphertext and tag  verification and decrypt Time (AES-128-GCM-VRF')
plt.xlabel('Size of Plaintext Message (bytes)')
plt.ylabel('Time (ms)')
plt.title('Time Taken for tag generation verification and encryption and decrypt   vs. Size of Plaintext Message')
plt.legend()
plt.grid(True)
plt.show()
# cipher , tag = crypto_instance.encrypt_generate_auth("AES-128-GCM-GEN",symmetric_key,symmetric_key,plaintext_message,nonce_aes_gcm)
# plain , valid = crypto_instance.decrypt_verify_auth("AES-128-GCM-VRF",symmetric_key,symmetric_key,cipher,nonce_aes_gcm,tag)
