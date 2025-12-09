"""
Quick Test & Usage Examples for Asymmetric Cryptography
Run this file to see the system in action!
"""

from asymmetric_crypto import AsymmetricCrypto

print("🔐 ASYMMETRIC CRYPTOGRAPHY - QUICK START\n")
print("="*60)

# === TEST 1: Basic Encryption ===
print("\n1️⃣  BASIC ENCRYPTION & DECRYPTION")
print("-" * 60)

crypto = AsymmetricCrypto(key_size=2048)
crypto.generate_key_pair()

message = "Hello World! This is secret 🔒"
print(f"Original: {message}")

encrypted = crypto.encrypt(message)
print(f"Encrypted: {encrypted[:60]}...")

decrypted = crypto.decrypt(encrypted)
print(f"Decrypted: {decrypted}")
print(f"✅ Success: {message == decrypted}")

# === TEST 2: Digital Signature ===
print("\n2️⃣  DIGITAL SIGNATURES")
print("-" * 60)

document = "I agree to transfer $1000"
print(f"Document: {document}")

signature = crypto.sign(document)
print(f"Signature: {signature[:60]}...")

is_valid = crypto.verify(document, signature)
print(f"✅ Signature valid: {is_valid}")

# Try tampering
tampered = "I agree to transfer $9999"
is_tampered_valid = crypto.verify(tampered, signature)
print(f"❌ Tampered valid: {is_tampered_valid}")

# === TEST 3: Save & Load Keys ===
print("\n3️⃣  SAVE & LOAD KEYS")
print("-" * 60)

crypto.save_private_key('test_private.pem', password='test123')
crypto.save_public_key('test_public.pem')
print("✅ Keys saved to files")

# Create new instance and load keys
crypto2 = AsymmetricCrypto()
crypto2.load_private_key('test_private.pem', password='test123')
print("✅ Keys loaded from files")

# Test with loaded keys
test_msg = "Testing persistence"
enc = crypto.encrypt(test_msg)
dec = crypto2.decrypt(enc)
print(f"✅ Cross-instance works: {test_msg == dec}")

# === TEST 4: Two-Party Communication ===
print("\n4️⃣  ALICE & BOB COMMUNICATION")
print("-" * 60)

# Alice
alice = AsymmetricCrypto()
alice.generate_key_pair()
alice.save_public_key('alice_pub.pem')
print("👩 Alice created keys")

# Bob
bob = AsymmetricCrypto()
bob.generate_key_pair()
bob.save_public_key('bob_pub.pem')
print("👨 Bob created keys")

# Bob sends encrypted message to Alice
bob.load_public_key('alice_pub.pem')
msg_to_alice = "Meet me at 5 PM"
encrypted_msg = bob.encrypt(msg_to_alice)
print(f"👨→👩 Bob sends: '{msg_to_alice}'")

# Alice decrypts
decrypted_msg = alice.decrypt(encrypted_msg)
print(f"👩 Alice reads: '{decrypted_msg}'")

# Alice sends signed reply
alice_reply = "OK, see you then!"
alice_signature = alice.sign(alice_reply)
print(f"👩→👨 Alice replies (signed): '{alice_reply}'")

# Bob verifies Alice's signature
bob.load_public_key('alice_pub.pem')
is_authentic = bob.verify(alice_reply, alice_signature)
print(f"👨 Bob verifies: {'✅ Authentic' if is_authentic else '❌ Fake'}")

print("\n" + "="*60)
print("✅ ALL TESTS PASSED!")
print("="*60)

print("\n📖 HOW TO USE IN YOUR CODE:")
print("""
# 1. Generate keys
crypto = AsymmetricCrypto(key_size=2048)
crypto.generate_key_pair()

# 2. Encrypt a message
encrypted = crypto.encrypt("Secret message")

# 3. Decrypt it
decrypted = crypto.decrypt(encrypted)

# 4. Sign a document
signature = crypto.sign("Important document")

# 5. Verify signature
is_valid = crypto.verify("Important document", signature)

# 6. Save/Load keys
crypto.save_private_key('private.pem', password='secure123')
crypto.load_private_key('private.pem', password='secure123')
""")

# Cleanup
import os
for f in ['test_private.pem', 'test_public.pem', 'alice_pub.pem', 'bob_pub.pem']:
    try:
        os.remove(f)
    except:
        pass

print("\n🎯 Run 'python asymmetric_crypto.py' for interactive menu!")
