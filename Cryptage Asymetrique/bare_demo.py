"""
BARE DEMO - Symmetric and Asymmetric Cryptography
Simple demonstration without tutorial
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
import os
import base64

# ============================================================
# SYMMETRIC ENCRYPTION (AES-256-CBC)
# ============================================================

print("=" * 60)
print("SYMMETRIC ENCRYPTION - AES-256-CBC")
print("=" * 60)

# Generate key
key = os.urandom(32)  # 256 bits
iv = os.urandom(16)   # 128 bits
print(f"\nAES Key: {key.hex()}")
print(f"IV: {iv.hex()}")

# Message
message = "Secret AES message"
print(f"\nOriginal message: {message}")

# Encrypt
padder = sym_padding.PKCS7(128).padder()
padded = padder.update(message.encode()) + padder.finalize()
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded) + encryptor.finalize()
encrypted_b64 = base64.b64encode(iv + ciphertext).decode()
print(f"Encrypted: {encrypted_b64}")

# Decrypt
data = base64.b64decode(encrypted_b64)
iv_dec, ct = data[:16], data[16:]
cipher = Cipher(algorithms.AES(key), modes.CBC(iv_dec), backend=default_backend())
decryptor = cipher.decryptor()
padded_dec = decryptor.update(ct) + decryptor.finalize()
unpadder = sym_padding.PKCS7(128).unpadder()
decrypted = (unpadder.update(padded_dec) + unpadder.finalize()).decode()
print(f"Decrypted: {decrypted}")

# ============================================================
# ASYMMETRIC ENCRYPTION (RSA-2048-OAEP)
# ============================================================

print("\n" + "=" * 60)
print("ASYMMETRIC ENCRYPTION - RSA-2048-OAEP")
print("=" * 60)

# Generate key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Show keys
pub_numbers = public_key.public_numbers()
print(f"\nPublic key (e): {pub_numbers.e}")
print(f"Public key (n): {str(pub_numbers.n)[:50]}...")

# Message
message_rsa = "Secret RSA message"
print(f"\nOriginal message: {message_rsa}")

# Encrypt with public key
ciphertext_rsa = public_key.encrypt(
    message_rsa.encode(),
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
encrypted_rsa_b64 = base64.b64encode(ciphertext_rsa).decode()
print(f"Encrypted: {encrypted_rsa_b64[:60]}...")

# Decrypt with private key
decrypted_rsa = private_key.decrypt(
    ciphertext_rsa,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
).decode()
print(f"Decrypted: {decrypted_rsa}")

# ============================================================
# FILE ENCRYPTION (AES)
# ============================================================

print("\n" + "=" * 60)
print("FILE ENCRYPTION")
print("=" * 60)

# Create file
content = "Confidential file content"
with open("test_file.txt", "w") as f:
    f.write(content)
print(f"\nFile created: test_file.txt")
print(f"Content: {content}")

# Encrypt file
with open("test_file.txt", "rb") as f:
    file_data = f.read()

key_file = os.urandom(32)
iv_file = os.urandom(16)
padder = sym_padding.PKCS7(128).padder()
padded_file = padder.update(file_data) + padder.finalize()
cipher = Cipher(algorithms.AES(key_file), modes.CBC(iv_file), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_file = encryptor.update(padded_file) + encryptor.finalize()

with open("test_file.enc", "wb") as f:
    f.write(iv_file + encrypted_file)
print(f"Encrypted file: test_file.enc")

# Decrypt file
with open("test_file.enc", "rb") as f:
    enc_data = f.read()

iv_dec = enc_data[:16]
ct_file = enc_data[16:]
cipher = Cipher(algorithms.AES(key_file), modes.CBC(iv_dec), backend=default_backend())
decryptor = cipher.decryptor()
padded_dec = decryptor.update(ct_file) + decryptor.finalize()
unpadder = sym_padding.PKCS7(128).unpadder()
decrypted_file = unpadder.update(padded_dec) + unpadder.finalize()

with open("test_file_dec.txt", "wb") as f:
    f.write(decrypted_file)
print(f"Decrypted file: test_file_dec.txt")
print(f"Content: {decrypted_file.decode()}")

print("\n" + "=" * 60)
print("END")
print("=" * 60)
