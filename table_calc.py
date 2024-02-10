import execute_crypto
import random , string
import time
crypto_instance = execute_crypto.ExecuteCrypto()

# Generate keys
symmetric_key, \
public_key_sender_rsa, private_key_sender_rsa, \
public_key_receiver_rsa, private_key_receiver_rsa, \
public_key_sender_ecc, private_key_sender_ecc = crypto_instance.generate_keys()

# Generate nonces
nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm = crypto_instance.generate_nonces()

# Encryption and Decryption Example
plaintext_message = "Paris 2024 will see a new vision of Olympism in action, delivered in a unique spirit of international celebration."
# Open the file in write mode
with open("output.txt", "w") as f:
    # Write the sentence to the file


    start_time = time.time()
    auth_tag_cmac = crypto_instance.generate_auth_tag('AES-128-CMAC-GEN', symmetric_key, plaintext_message, nonce_aes_cmac)
    end_time = time.time()
    time1_1 = end_time -start_time
    start_time = time.time()
    is_verified_cmac = crypto_instance.verify_auth_tag('AES-128-CMAC-VRF', symmetric_key, plaintext_message, nonce_aes_cmac, auth_tag_cmac)
    end_time = time.time()
    packet_length1 = len(auth_tag_cmac) + len(plaintext_message)
    time1_2 = end_time -start_time
    keylen1_1 = len(symmetric_key)
    keylen1_2 = len(symmetric_key)
    f.write(f"packet_length :{packet_length1}\n time1_1 :{time1_1*1000} \n time1_2:{time1_2*1000} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2} \n")

    # print(f"packet_length :{packet_length1}\n time1_1 :{time1_1} \n time1_2:{time1_2} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2}")


    start_time = time.time()
    auth_tag_hmac = crypto_instance.generate_auth_tag('SHA3-256-HMAC-GEN', symmetric_key, plaintext_message, nonce_hmac)
    end_time = time.time()
    time1_1 = end_time -start_time
    start_time = time.time()
    is_verified_hmac = crypto_instance.verify_auth_tag('SHA3-256-HMAC-VRF', symmetric_key, plaintext_message, nonce_hmac, auth_tag_hmac)
    end_time = time.time()
    packet_length1 = len(auth_tag_cmac) + len(plaintext_message)
    time1_2 = end_time -start_time
    keylen1_1 = len(symmetric_key)
    keylen1_2 = len(symmetric_key)
    f.write(f"packet_length :{packet_length1}\n time1_1 :{time1_1*1000} \n time1_2:{time1_2*1000} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2} \n")

    # print(f"packet_length :{packet_length1}\n time1_1 :{time1_1} \n time1_2:{time1_2} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2}")


    start_time = time.time()
    auth_rsa_sha = crypto_instance.generate_auth_tag('RSA-2048-SHA3-256-SIG-GEN', private_key_sender_rsa, plaintext_message, nonce_tag_rsa)
    end_time = time.time()
    time1_1 = end_time -start_time
    start_time = time.time()
    is_verified_rsa_sha = crypto_instance.verify_auth_tag('RSA-2048-SHA3-256-SIG-VRF', public_key_sender_rsa, plaintext_message, nonce_tag_rsa, auth_rsa_sha)
    end_time = time.time()
    packet_length1 = len(auth_tag_cmac) + len(plaintext_message)
    time1_2 = end_time -start_time
    keylen1_1 = (private_key_sender_rsa).key_size
    keylen1_2 = (public_key_sender_rsa).key_size
    f.write(f"packet_length :{packet_length1}\n time1_1 :{time1_1*1000} \n time1_2:{time1_2*1000} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2} \n")




    start_time = time.time()
    auth_ecdsa_sha = crypto_instance.generate_auth_tag('ECDSA-256-SHA3-256-SIG-GEN', private_key_sender_ecc, plaintext_message, nonce_ecdsa)
    end_time = time.time()
    time1_1 = end_time -start_time
    start_time = time.time()
    is_verified_ecdsa_sha = crypto_instance.verify_auth_tag('ECDSA-256-SHA3-256-SIG-VRF', public_key_sender_ecc, plaintext_message, nonce_ecdsa, auth_ecdsa_sha)
    end_time = time.time()
    packet_length1 = len(auth_tag_cmac) + len(plaintext_message)
    time1_2 = end_time -start_time
    keylen1_1 = (private_key_sender_ecc).key_size
    keylen1_2 = (public_key_sender_ecc).key_size
    f.write(f"packet_length :{packet_length1}\n time1_1 :{time1_1*1000} \n time1_2:{time1_2*1000} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2} \n")



    start_time = time.time()
    ciphertext_aes_cbc = crypto_instance.encrypt('AES-128-CBC-ENC', symmetric_key, plaintext_message, nonce_aes_cbc)
    end_time = time.time()
    time1_1 = end_time -start_time
    start_time = time.time()
    decrypted_aes_cbc = crypto_instance.decrypt('AES-128-CBC-DEC', symmetric_key, ciphertext_aes_cbc, nonce_aes_cbc)
    end_time = time.time()
    packet_length1 = len(ciphertext_aes_cbc) 
    time1_2 = end_time -start_time
    keylen1_1 = len(symmetric_key)
    keylen1_2 = len(symmetric_key)
    f.write(f"packet_length :{packet_length1}\n time1_1 :{time1_1*1000} \n time1_2:{time1_2*1000} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2} \n")

    # AES-128-CBC Encryption and Decryption

    start_time = time.time()
    encrypted_aes_ctr = crypto_instance.encrypt('AES-128-CTR-ENC', symmetric_key, plaintext_message, nonce_aes_ctr)
    end_time = time.time()
    time1_1 = end_time -start_time
    start_time = time.time()
    decrypted_aes_ctr = crypto_instance.decrypt('AES-128-CTR-DEC', symmetric_key, encrypted_aes_ctr, nonce_aes_ctr)
    end_time = time.time()
    packet_length1 = len(ciphertext_aes_cbc) 
    time1_2 = end_time -start_time
    keylen1_1 = len(symmetric_key)
    keylen1_2 = len(symmetric_key)
    f.write(f"packet_length :{packet_length1}\n time1_1 :{time1_1*1000} \n time1_2:{time1_2*1000} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2} \n")

    # AES-128-CTR Encryption and Decryption

    # RSA-2048 Encryption and Decryption
    start_time = time.time()
    encrypted_rsa = crypto_instance.encrypt('RSA-2048-ENC', public_key_receiver_rsa, plaintext_message, nonce_encrypt_rsa)
    end_time = time.time()
    time1_1 = end_time -start_time
    start_time = time.time()
    decrypted_rsa = crypto_instance.decrypt('RSA-2048-DEC', private_key_receiver_rsa, encrypted_rsa, nonce_encrypt_rsa)
    end_time = time.time()
    packet_length1 = len(ciphertext_aes_cbc) 
    time1_2 = end_time -start_time
    keylen1_1 = (public_key_receiver_rsa).key_size
    keylen1_2 = (private_key_receiver_rsa).key_size
    f.write(f"packet_length :{packet_length1}\n time1_1 :{time1_1*1000} \n time1_2:{time1_2*1000} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2} \n")


    #Encrypt and authenticate AES-GCM 
    start_time = time.time()
    cipher , tag = crypto_instance.encrypt_generate_auth("AES-128-GCM-GEN",symmetric_key,symmetric_key,plaintext_message,nonce_aes_gcm)
    end_time = time.time()
    time1_1 = end_time -start_time
    start_time = time.time()
    plain , valid = crypto_instance.decrypt_verify_auth("AES-128-GCM-VRF",symmetric_key,symmetric_key,cipher,nonce_aes_gcm,tag)
    end_time = time.time()
    packet_length1 = len(cipher) + len(tag) 
    time1_2 = end_time -start_time
    keylen1_1 = len(symmetric_key)
    keylen1_2 = len(symmetric_key)
    f.write(f"packet_length :{packet_length1}\n time1_1 :{time1_1*1000} \n time1_2:{time1_2*1000} \n keylen1_1 : {keylen1_1} \n keylen1_2 :{keylen1_2} \n")

