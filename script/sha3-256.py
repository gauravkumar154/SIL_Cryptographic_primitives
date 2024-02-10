import hashlib

def sha3_256_hash(data):
    sha3_256 = hashlib.sha3_256()
    sha3_256.update(data.encode('utf-8'))
    return sha3_256.hexdigest()

# Example usage
data = "Hello, SHA-3!"
hash_result = sha3_256_hash(data)

print("Original Data:", data)
print("SHA-3 (SHA3-256) Hash:", hash_result)