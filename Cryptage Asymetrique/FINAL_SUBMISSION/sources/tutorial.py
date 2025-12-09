from asymmetric_crypto import AsymmetricCrypto
import os

def print_section(title, num):
    print(f"\n{'='*70}")
    print(f"STEP {num}: {title}")
    print(f"{'='*70}\n")

def print_explanation(text):
    print(f"📚 {text}\n")

def print_code(code):
    print("💻 CODE:")
    print(f"   {code}\n")

def wait_input():
    input("Press ENTER to continue...")


print_section("Generating an RSA Key Pair", 1)

print_explanation("""
RSA (Rivest-Shamir-Adleman) uses TWO keys:

🔑 PUBLIC KEY: Anyone can see it. Used to ENCRYPT messages.
🔒 PRIVATE KEY: Only you have it. Used to DECRYPT messages.

Think of it like:
• Public key = mailbox (anyone can drop letters)
• Private key = mailbox key (only you can open it)

We'll create a 2048-bit RSA key pair. More bits = more secure but slower.
""")

print_code("crypto = AsymmetricCrypto(key_size=2048)")
print_code("crypto.generate_key_pair()")

crypto = AsymmetricCrypto(key_size=2048)
private_key, public_key = crypto.generate_key_pair()

print("✅ Keys generated successfully!\n")
print(f"Private key type: {type(private_key)}")
print(f"Public key type: {type(public_key)}\n")

wait_input()


print_section("Encrypting a Message with Public Key", 2)

print_explanation("""
Now let's encrypt a message using the PUBLIC key.

The steps are:
1. Take a plaintext message: "Hello World"
2. Use RSA-OAEP algorithm (Optimal Asymmetric Encryption Padding)
3. Output: Random-looking encrypted garbage (ciphertext)

Key point: Even with the same message, encryption is RANDOM!
Each encryption produces different ciphertext.
""")

message = "Hello World! 🌍"
print(f"Original message: '{message}'")
print(f"Message length: {len(message)} bytes\n")

print_code("encrypted = crypto.encrypt(message)")
encrypted = crypto.encrypt(message)

print(f"Encrypted (base64): {encrypted}\n")
print(f"Encrypted length: {len(encrypted)} characters\n")

print_explanation("""
Notice: The encrypted message looks like random noise!
You can't read it without the PRIVATE KEY.

The message is encoded as base64 for easy storage/transmission.
""")

wait_input()


print_section("Decrypting with Private Key", 3)

print_explanation("""
Now let's decrypt using the PRIVATE KEY.

Only someone with the private key can read this encrypted message!
This is the core of asymmetric cryptography security.
""")

print_code("decrypted = crypto.decrypt(encrypted)")
decrypted = crypto.decrypt(encrypted)

print(f"Decrypted message: '{decrypted}'\n")
print(f"✅ Original == Decrypted: {message == decrypted}\n")

print_explanation("""
Perfect! We got the original message back.

This demonstrates the encryption/decryption cycle:
PLAINTEXT → (encrypt with public key) → CIPHERTEXT → (decrypt with private key) → PLAINTEXT
""")

wait_input()


print_section("Demonstrating Encryption Randomness", 4)

print_explanation("""
Let's encrypt the SAME message twice.
With RSA-OAEP, each encryption is random, so we get different outputs!

This is IMPORTANT for security: an attacker can't just encrypt many guesses
and compare - each encryption is unique.
""")

msg = "Secret"
print(f"Message: '{msg}'\n")

enc1 = crypto.encrypt(msg)
enc2 = crypto.encrypt(msg)

print(f"Encryption #1: {enc1[:50]}...")
print(f"Encryption #2: {enc2[:50]}...\n")

print(f"Are they the same? {enc1 == enc2}")
print(f"But both decrypt to same message? {crypto.decrypt(enc1) == crypto.decrypt(enc2)}\n")

print_explanation("""
✅ Each encryption is UNIQUE (randomness)
✅ But all decrypt to SAME message (correctness)

This is why RSA with OAEP is secure!
""")

wait_input()


print_section("Creating a Digital Signature", 5)

print_explanation("""
Digital signatures prove:
✅ WHO created the message (authentication)
✅ Message wasn't changed (integrity)

Process:
1. Use PRIVATE key to SIGN a message
2. Anyone with PUBLIC key can VERIFY the signature
3. Only you can create signatures (only you have private key)
4. Anyone can verify (public key is public)

Think of it like your handwritten signature on a check!
""")

document = "I agree to pay $100"
print(f"Document: '{document}'\n")

print_code("signature = crypto.sign(document)")
signature = crypto.sign(document)

print(f"Signature (base64): {signature[:60]}...\n")

wait_input()


print_section("Verifying the Signature", 6)

print_explanation("""
Now anyone with the PUBLIC key can verify this signature.

If the signature is valid → Document wasn't changed
If signature is invalid → Either:
  • Document was modified
  • Signature was forged
  • Wrong public key
""")

print_code("is_valid = crypto.verify(document, signature)")
is_valid = crypto.verify(document, signature)

print(f"Signature valid? {is_valid}\n")

print_explanation("""
✅ Signature verified! The document is authentic.

Now let's try to tamper with the document...
""")

wait_input()


print_section("Detecting Document Tampering", 7)

print_explanation("""
If someone changes even ONE CHARACTER, the signature becomes invalid!

Let's try verifying with a MODIFIED document.
""")

tampered_doc = "I agree to pay $1000"
print(f"Original document:  '{document}'")
print(f"Tampered document:  '{tampered_doc}'\n")

print_code("is_valid = crypto.verify(tampered_doc, signature)")
is_valid_tampered = crypto.verify(tampered_doc, signature)

print(f"Tampered signature valid? {is_valid_tampered}\n")

print_explanation("""
❌ Invalid! The signature doesn't match the tampered document.

This proves:
✅ The original document was authentic
❌ The tampered version is fake

Digital signatures are TAMPERING-PROOF!
""")

wait_input()


print_section("Saving and Loading Keys to Files", 8)

print_explanation("""
You can save keys to files for later use:
• Private key: Keep SECURE (with password)
• Public key: Share publicly

Process:
1. Generate keys
2. Save to files
3. Later: Load from files in different program/session
4. Use loaded keys normally
""")

print_code("crypto.save_private_key('my_private.pem', password='MyPassword123')")
print_code("crypto.save_public_key('my_public.pem')")

crypto.save_private_key('my_private.pem', password='MyPassword123')
crypto.save_public_key('my_public.pem')

print("✅ Keys saved!\n")

print(f"Private key file size: {os.path.getsize('my_private.pem')} bytes")
print(f"Public key file size: {os.path.getsize('my_public.pem')} bytes\n")

print_explanation("""
Notice: The private key file is larger because it contains more data.
Both files are in PEM format (text-based cryptographic format).
""")

wait_input()


print_section("Loading Keys from Files", 9)

print_explanation("""
Now let's create a NEW crypto instance and load the saved keys.
This simulates loading keys in a different program/session.
""")

crypto2 = AsymmetricCrypto()
print("Created new AsymmetricCrypto instance\n")

print_code("crypto2.load_private_key('my_private.pem', password='MyPassword123')")
crypto2.load_private_key('my_private.pem', password='MyPassword123')

print("✅ Private key loaded!\n")

print_explanation("""
Now crypto2 has the same keys as crypto1.
Let's test if they can decrypt messages!
""")

wait_input()


print_section("Encrypting with One Instance, Decrypting with Another", 10)

print_explanation("""
Instance 1 encrypts a message.
Instance 2 (with loaded keys) decrypts it.

This proves the keys are identical!
""")

secret_msg = "This is a secret message! 🔐"
print(f"Original message: '{secret_msg}'\n")

print_code("# Instance 1 encrypts")
encrypted_by_1 = crypto.encrypt(secret_msg)
print(f"Encrypted by Instance 1: {encrypted_by_1[:50]}...\n")

print_code("# Instance 2 decrypts")
decrypted_by_2 = crypto2.decrypt(encrypted_by_1)
print(f"Decrypted by Instance 2: '{decrypted_by_2}'\n")

print(f"✅ Match: {secret_msg == decrypted_by_2}\n")

print_explanation("""
Perfect! Keys persist across sessions and instances.
This is how you can:
• Encrypt on one computer, decrypt on another
• Share public key with others
• Store private key securely
""")

wait_input()


print_section("Secure Communication Between Alice & Bob", 11)

print_explanation("""
Let's simulate secure communication between two people:

ALICE:
1. Generates her own RSA keys
2. Shares her PUBLIC key with Bob

BOB:
1. Generates his own RSA keys
2. Shares his PUBLIC key with Alice

Then they can:
✅ Send encrypted messages (only recipient can read)
✅ Sign messages (only sender could have created)
""")

alice = AsymmetricCrypto()
alice.generate_key_pair()
print("👩 ALICE: Generated keys")
print("👩 ALICE: Sharing public key with Bob...\n")

bob = AsymmetricCrypto()
bob.generate_key_pair()
print("👨 BOB: Generated keys")
print("👨 BOB: Sharing public key with Alice...\n")

alice.save_public_key('alice_public.pem')
bob.save_public_key('bob_public.pem')

wait_input()


print_section("Bob Sends Encrypted Message to Alice", 12)

print_explanation("""
Bob wants to send a SECRET message to Alice.

Process:
1. Bob loads Alice's PUBLIC key
2. Bob encrypts the message using Alice's public key
3. Alice can decrypt using her PRIVATE key
4. Only Alice can read it (only she has the private key)
""")

bob.load_public_key('alice_public.pem')
print("👨 BOB: Loaded Alice's public key\n")

msg_for_alice = "Hey Alice! Let's meet at 3 PM 🤝"
print(f"👨 BOB: Message to Alice: '{msg_for_alice}'\n")

print_code("encrypted_msg = bob.encrypt(msg_for_alice)")
encrypted_msg = bob.encrypt(msg_for_alice)
print(f"👨 BOB: Encrypted: {encrypted_msg[:50]}...\n")

print_explanation("""
The encrypted message is sent to Alice (over internet, doesn't matter if intercepted).
Only Alice can decrypt it!
""")

wait_input()

print_code("decrypted_msg = alice.decrypt(encrypted_msg)")
decrypted_msg = alice.decrypt(encrypted_msg)
print(f"👩 ALICE: Received: '{decrypted_msg}'\n")

print_explanation("""
✅ Alice received the secret message!

An attacker who intercepts the encrypted message can't read it
(they don't have Alice's private key).
""")

wait_input()


print_section("Alice Sends Signed Reply to Bob", 13)

print_explanation("""
Now Alice wants to send a reply that Bob can verify came from her.

Process:
1. Alice SIGNS the message with her PRIVATE key
2. Alice sends the signed message
3. Bob loads Alice's PUBLIC key
4. Bob VERIFIES the signature with her public key
5. Bob knows it came from Alice (only she has her private key)
""")

alice_reply = "Sounds good! See you then 👍"
print(f"👩 ALICE: Message to Bob: '{alice_reply}'\n")

print_code("signature = alice.sign(alice_reply)")
signature = alice.sign(alice_reply)
print(f"👩 ALICE: Signature created\n")

print_explanation("""
Alice sends both:
• The message (plain text, anyone can see)
• The signature (proof it came from Alice)
""")

wait_input()

bob.load_public_key('alice_public.pem')
print("👨 BOB: Loaded Alice's public key\n")

print_code("is_authentic = bob.verify(alice_reply, signature)")
is_authentic = bob.verify(alice_reply, signature)

print(f"👨 BOB: Message authentic? {is_authentic}\n")

print_explanation("""
✅ Bob verified the signature!

Now Bob knows:
✅ The message came from Alice (only she could sign it)
✅ The message wasn't changed (signature would fail)

This is AUTHENTICATION + INTEGRITY CHECK!
""")

wait_input()


print_section("Summary: What We Learned", 14)

print_explanation("""
🔐 ASYMMETRIC CRYPTOGRAPHY KEY CONCEPTS:

1. KEY PAIR:
   • PUBLIC key: For encrypting messages
   • PRIVATE key: For decrypting messages (keep secret!)

2. ENCRYPTION:
   • Anyone can encrypt (public key is public)
   • Only you can decrypt (only you have private key)
   • Each encryption is random (secure against pattern analysis)

3. DIGITAL SIGNATURES:
   • Only you can sign (need private key)
   • Anyone can verify (public key is public)
   • Proves authenticity and integrity

4. PRACTICAL USE CASES:
   ✅ Send secret messages (encryption)
   ✅ Prove who you are (signatures)
   ✅ HTTPS/SSL (web security)
   ✅ Email encryption (PGP)
   ✅ Bitcoin/Blockchain (digital signatures)
   ✅ Document signing

5. SECURITY PROPERTIES:
   ✅ Confidentiality (encryption keeps secrets)
   ✅ Authentication (signatures prove identity)
   ✅ Non-repudiation (can't deny signing)
   ✅ Integrity (can't change signed messages)

6. KEY SIZES:
   • 2048-bit: Good for most uses
   • 3072-bit: Better for long-term security
   • 4096-bit: Extra security (slower)
""")

os.remove('my_private.pem')
os.remove('my_public.pem')
os.remove('alice_public.pem')
os.remove('bob_public.pem')

print("\n" + "="*70)
print("✅ TUTORIAL COMPLETE!")
print("="*70)

print("""
🎯 NEXT STEPS:

1. Read the asymmetric_crypto.py source code
2. Try the interactive menu:
   python asymmetric_crypto.py
   
3. Experiment with:
   • Different key sizes
   • Encrypt large messages
   • Create certificate chains
   • Build secure communication systems

4. Real-world applications:
   • Encrypt sensitive files
   • Sign documents
   • Implement API authentication
   • Build secure messaging apps

Questions? Check the docstrings in asymmetric_crypto.py!
""")
