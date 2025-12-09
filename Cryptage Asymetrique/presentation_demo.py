"""
=================================================================
PRESENTATION DEMO: Symmetric vs Asymmetric Cryptography
=================================================================
Author: Ahmed Dinari
Purpose: Demonstrate encryption/decryption for presentation

This script demonstrates:
1. SYMMETRIC ENCRYPTION (AES) - Same key for encrypt/decrypt
2. ASYMMETRIC ENCRYPTION (RSA) - Public/Private key pair
3. FILE ENCRYPTION - Encrypt and decrypt actual files
=================================================================
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
import os
import base64

# ============================================================
# PART 1: SYMMETRIC ENCRYPTION (AES)
# ============================================================

class SymmetricCrypto:
    """Symmetric encryption using AES (Advanced Encryption Standard)"""
    
    def __init__(self):
        # Generate a random 256-bit key (32 bytes)
        self.key = os.urandom(32)
        print(f"🔑 AES Key generated: {self.key.hex()[:32]}...")
    
    def encrypt(self, plaintext):
        """Encrypt using AES-CBC"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate random IV (Initialization Vector)
        iv = os.urandom(16)
        
        # Pad the plaintext to be multiple of block size (16 bytes)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Create cipher and encrypt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Prepend IV to ciphertext
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    def decrypt(self, ciphertext_b64):
        """Decrypt using AES-CBC"""
        data = base64.b64decode(ciphertext_b64)
        
        # Extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        # Create cipher and decrypt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext.decode('utf-8')


# ============================================================
# PART 2: ASYMMETRIC ENCRYPTION (RSA)
# ============================================================

class AsymmetricCrypto:
    """Asymmetric encryption using RSA"""
    
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self):
        """Generate RSA key pair"""
        print(f"🔐 Generating {self.key_size}-bit RSA key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("✅ RSA key pair generated!")
        return self.private_key, self.public_key
    
    def encrypt(self, plaintext):
        """Encrypt with public key (RSA-OAEP)"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        ciphertext = self.public_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def decrypt(self, ciphertext_b64):
        """Decrypt with private key"""
        ciphertext = base64.b64decode(ciphertext_b64)
        
        plaintext = self.private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')


# ============================================================
# PART 3: FILE ENCRYPTION
# ============================================================

def encrypt_file_symmetric(input_file, output_file, crypto):
    """Encrypt a file using symmetric encryption"""
    with open(input_file, 'rb') as f:
        data = f.read()
    
    encrypted = crypto.encrypt(data.decode('utf-8', errors='replace'))
    
    with open(output_file, 'w') as f:
        f.write(encrypted)
    
    print(f"✅ File encrypted: {input_file} → {output_file}")


def decrypt_file_symmetric(input_file, output_file, crypto):
    """Decrypt a file using symmetric encryption"""
    with open(input_file, 'r') as f:
        encrypted_data = f.read()
    
    decrypted = crypto.decrypt(encrypted_data)
    
    with open(output_file, 'w') as f:
        f.write(decrypted)
    
    print(f"✅ File decrypted: {input_file} → {output_file}")


# ============================================================
# MAIN DEMONSTRATION
# ============================================================

def main():
    print("\n" + "="*70)
    print("🔐 CRYPTOGRAPHY PRESENTATION DEMO")
    print("="*70)
    
    # ---------------------------------------------------------
    # DEMO 1: SYMMETRIC ENCRYPTION (AES)
    # ---------------------------------------------------------
    print("\n" + "-"*70)
    print("📌 PART 1: SYMMETRIC ENCRYPTION (AES)")
    print("-"*70)
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║  SAME KEY for encryption AND decryption                         ║
    ║                                                                  ║
    ║  Text → [SECRET KEY] → Encrypted → [SECRET KEY] → Text         ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    input("[Press ENTER to generate AES key...]")
    
    # Step 1: Generate Key
    print("\n" + "~"*50)
    print("STEP 1: KEY GENERATION")
    print("~"*50)
    sym_crypto = SymmetricCrypto()
    print(f"\n🔑 AES Key (256 bits) generated:")
    print(f"   HEX: {sym_crypto.key.hex()}")
    print(f"   Size: {len(sym_crypto.key) * 8} bits ({len(sym_crypto.key)} bytes)")
    
    input("\n[Press ENTER to see the original message...]")
    
    # Step 2: Original Message
    print("\n" + "~"*50)
    print("STEP 2: ORIGINAL MESSAGE")
    print("~"*50)
    message_sym = "Hello! This is a secret message 🔒"
    print(f"\n📄 Message: {message_sym}")
    print(f"   Size: {len(message_sym.encode('utf-8'))} bytes")
    print(f"   Bytes: {message_sym.encode('utf-8')}")
    
    input("\n[Press ENTER to encrypt...]")
    
    # Step 3: Encryption Process
    print("\n" + "~"*50)
    print("STEP 3: ENCRYPTION PROCESS")
    print("~"*50)
    print("\n   1️⃣  Message → Convert to bytes")
    print(f"      {message_sym.encode('utf-8')[:50]}...")
    print("\n   2️⃣  Generate random IV (Initialization Vector)")
    
    # Show IV generation
    iv_demo = os.urandom(16)
    print(f"      IV: {iv_demo.hex()}")
    print(f"      IV Size: 16 bytes (128 bits)")
    
    print("\n   3️⃣  Apply PKCS7 padding (multiple of 16 bytes)")
    print("\n   4️⃣  Encrypt with AES-256-CBC")
    print(f"      Key: {sym_crypto.key.hex()[:32]}...")
    
    encrypted_sym = sym_crypto.encrypt(message_sym)
    print(f"\n🔒 ENCRYPTED RESULT (Base64):")
    print(f"   {encrypted_sym}")
    print(f"\n   Encrypted size: {len(encrypted_sym)} characters")
    
    input("\n[Press ENTER to decrypt...]")
    
    # Step 4: Decryption Process
    print("\n" + "~"*50)
    print("STEP 4: DECRYPTION PROCESS")
    print("~"*50)
    print("\n   1️⃣  Decode Base64 → bytes")
    print("\n   2️⃣  Extract IV (first 16 bytes)")
    print("\n   3️⃣  Decrypt with AES-256-CBC + same key")
    print(f"      Key: {sym_crypto.key.hex()[:32]}...")
    print("\n   4️⃣  Remove PKCS7 padding")
    
    decrypted_sym = sym_crypto.decrypt(encrypted_sym)
    print(f"\n🔓 DECRYPTED RESULT:")
    print(f"   {decrypted_sym}")
    
    print(f"\n✅ Verification: {message_sym == decrypted_sym}")
    
    input("\n[Press ENTER to continue...]")
    
    # ---------------------------------------------------------
    # DEMO 2: ASYMMETRIC ENCRYPTION (RSA)
    # ---------------------------------------------------------
    print("\n" + "-"*70)
    print("📌 PART 2: ASYMMETRIC ENCRYPTION (RSA)")
    print("-"*70)
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║  TWO DIFFERENT KEYS:                                            ║
    ║  • PUBLIC Key   → to encrypt (anyone can have it)               ║
    ║  • PRIVATE Key  → to decrypt (only you have it)                 ║
    ║                                                                  ║
    ║  Text → [PUBLIC KEY] → Encrypted → [PRIVATE KEY] → Text        ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    input("[Press ENTER to generate RSA keys...]")
    
    # Step 1: Generate Key Pair
    print("\n" + "~"*50)
    print("STEP 1: KEY PAIR GENERATION")
    print("~"*50)
    
    asym_crypto = AsymmetricCrypto(key_size=2048)
    asym_crypto.generate_keys()
    
    # Show public key
    public_pem = asym_crypto.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    print(f"\n🔓 PUBLIC KEY (can be shared):")
    print("-"*50)
    for line in public_pem.split('\n')[:6]:
        print(f"   {line}")
    print("   ...")
    print(f"   Size: 2048 bits")
    
    # Show private key info
    print(f"\n🔐 PRIVATE KEY (must remain secret):")
    print("-"*50)
    print("   -----BEGIN PRIVATE KEY-----")
    print("   [SECRET CONTENT - NEVER SHARE]")
    print("   -----END PRIVATE KEY-----")
    print(f"   Size: 2048 bits")
    
    # Show key numbers
    pub_numbers = asym_crypto.public_key.public_numbers()
    print(f"\n📊 MATHEMATICAL PARAMETERS:")
    print(f"   e (public exponent): {pub_numbers.e}")
    print(f"   n (modulus): {str(pub_numbers.n)[:50]}...")
    print(f"   Size of n: {pub_numbers.n.bit_length()} bits")
    
    input("\n[Press ENTER to see the original message...]")
    
    # Step 2: Original Message
    print("\n" + "~"*50)
    print("STEP 2: ORIGINAL MESSAGE")
    print("~"*50)
    message_asym = "Secret RSA message! 🔐"
    print(f"\n📄 Message: {message_asym}")
    print(f"   Size: {len(message_asym.encode('utf-8'))} bytes")
    print(f"\n⚠️  RSA-2048 LIMIT: Maximum ~190 bytes per block")
    
    input("\n[Press ENTER to encrypt with PUBLIC key...]")
    
    # Step 3: Encryption with Public Key
    print("\n" + "~"*50)
    print("STEP 3: ENCRYPTION WITH PUBLIC KEY")
    print("~"*50)
    print("\n   1️⃣  Message → Convert to bytes")
    print(f"      {message_asym.encode('utf-8')}")
    print("\n   2️⃣  Apply OAEP padding (Optimal Asymmetric Encryption Padding)")
    print("      - Adds randomness for security")
    print("      - Uses SHA-256 for hashing")
    print("\n   3️⃣  Encrypt: C = M^e mod n")
    print(f"      e = {pub_numbers.e}")
    print(f"      n = {str(pub_numbers.n)[:30]}...")
    
    encrypted_asym = asym_crypto.encrypt(message_asym)
    print(f"\n🔒 ENCRYPTED RESULT (Base64):")
    print(f"   {encrypted_asym[:60]}...")
    print(f"   {encrypted_asym[60:120]}...")
    print(f"\n   Encrypted size: {len(base64.b64decode(encrypted_asym))} bytes (= 2048 bits)")
    
    input("\n[Press ENTER to decrypt with PRIVATE key...]")
    
    # Step 4: Decryption with Private Key
    print("\n" + "~"*50)
    print("STEP 4: DECRYPTION WITH PRIVATE KEY")
    print("~"*50)
    print("\n   1️⃣  Decode Base64 → encrypted bytes")
    print("\n   2️⃣  Decrypt: M = C^d mod n")
    print("      d = [SECRET PRIVATE KEY]")
    print(f"      n = {str(pub_numbers.n)[:30]}...")
    print("\n   3️⃣  Remove OAEP padding")
    print("\n   4️⃣  Convert bytes → Message")
    
    decrypted_asym = asym_crypto.decrypt(encrypted_asym)
    print(f"\n🔓 DECRYPTED RESULT:")
    print(f"   {decrypted_asym}")
    
    print(f"\n✅ Verification: {message_asym == decrypted_asym}")
    
    # Show that encryption is random
    print("\n" + "~"*50)
    print("🎲 DEMONSTRATION: RANDOM ENCRYPTION")
    print("~"*50)
    print("\nSame message encrypted 2 times gives DIFFERENT results:")
    enc1 = asym_crypto.encrypt(message_asym)
    enc2 = asym_crypto.encrypt(message_asym)
    print(f"\n   Encryption 1: {enc1[:40]}...")
    print(f"   Encryption 2: {enc2[:40]}...")
    print(f"\n   Identical? {enc1 == enc2} (thanks to random OAEP padding)")
    print(f"   But decrypt to same message? {asym_crypto.decrypt(enc1) == asym_crypto.decrypt(enc2)}")
    
    input("\n[Press ENTER to continue...]")
    
    # ---------------------------------------------------------
    # DEMO 3: FILE ENCRYPTION
    # ---------------------------------------------------------
    print("\n" + "-"*70)
    print("📌 PART 3: FILE ENCRYPTION")
    print("-"*70)
    
    # Create a test file
    test_content = """
    ============================================
    CONFIDENTIAL FILE
    ============================================
    
    Name: Ahmed Dinari
    Subject: Security Lab Work
    Date: November 2025
    
    This file contains sensitive information
    that must be protected by encryption.
    
    ============================================
    """
    
    # Write original file
    with open("original_file.txt", "w", encoding="utf-8") as f:
        f.write(test_content)
    print("📄 Original file created: original_file.txt")
    
    # Encrypt the file
    print("\n🔒 Encrypting the file...")
    encrypt_file_symmetric("original_file.txt", "encrypted_file.txt", sym_crypto)
    
    # Show encrypted content
    with open("encrypted_file.txt", "r") as f:
        encrypted_content = f.read()
    print(f"\n📄 Encrypted content (excerpt):\n   {encrypted_content[:80]}...")
    
    # Decrypt the file
    print("\n🔓 Decrypting the file...")
    decrypt_file_symmetric("encrypted_file.txt", "decrypted_file.txt", sym_crypto)
    
    # Verify
    with open("decrypted_file.txt", "r") as f:
        decrypted_content = f.read()
    
    print("\n✅ Decrypted content:")
    print(decrypted_content)
    
    # ---------------------------------------------------------
    # COMPARISON TABLE
    # ---------------------------------------------------------
    print("\n" + "-"*70)
    print("📌 COMPARISON: SYMMETRIC vs ASYMMETRIC")
    print("-"*70)
    print("""
    ┌────────────────────┬─────────────────────┬─────────────────────┐
    │     Criteria       │    SYMMETRIC        │    ASYMMETRIC       │
    ├────────────────────┼─────────────────────┼─────────────────────┤
    │ Number of keys     │ 1 (same key)        │ 2 (public/private)  │
    ├────────────────────┼─────────────────────┼─────────────────────┤
    │ Speed              │ Fast ⚡             │ Slow 🐢             │
    ├────────────────────┼─────────────────────┼─────────────────────┤
    │ Algorithms         │ AES, DES, 3DES      │ RSA, ECC, DSA       │
    ├────────────────────┼─────────────────────┼─────────────────────┤
    │ Key size           │ 128-256 bits        │ 2048-4096 bits      │
    ├────────────────────┼─────────────────────┼─────────────────────┤
    │ Key exchange       │ Difficult 😓        │ Easy ✅             │
    ├────────────────────┼─────────────────────┼─────────────────────┤
    │ Usage              │ Large volumes       │ Small messages      │
    ├────────────────────┼─────────────────────┼─────────────────────┤
    │ Examples           │ File encryption     │ HTTPS, Email, SSH   │
    └────────────────────┴─────────────────────┴─────────────────────┘
    """)
    
    print("\n" + "="*70)
    print("🎉 END OF DEMONSTRATION")
    print("="*70)
    print("""
    Files created:
    • original_file.txt   - Original file
    • encrypted_file.txt  - Encrypted file
    • decrypted_file.txt  - Decrypted file
    """)


if __name__ == "__main__":
    main()
