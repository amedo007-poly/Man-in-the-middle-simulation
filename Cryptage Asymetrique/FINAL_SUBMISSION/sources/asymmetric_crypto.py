from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import os


class AsymmetricCrypto:
    
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        
    def generate_key_pair(self):
        print(f"🔑 Generating {self.key_size}-bit RSA key pair...")
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        print("✅ Key pair generated successfully!")
        return self.private_key, self.public_key
    
    def save_private_key(self, filename, password=None):
        if self.private_key is None:
            raise ValueError("No private key to save. Generate keys first.")
        
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
        
        print(f"🔐 Private key saved to: {filename}")
    
    def save_public_key(self, filename):
        if self.public_key is None:
            raise ValueError("No public key to save. Generate keys first.")
        
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
        
        print(f"🔓 Public key saved to: {filename}")
    
    def load_private_key(self, filename, password=None):
        with open(filename, 'rb') as f:
            pem = f.read()
        
        pwd = password.encode() if password else None
        
        self.private_key = serialization.load_pem_private_key(
            pem,
            password=pwd,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        print(f"🔓 Private key loaded from: {filename}")
    
    def load_public_key(self, filename):
        with open(filename, 'rb') as f:
            pem = f.read()
        
        self.public_key = serialization.load_pem_public_key(
            pem,
            backend=default_backend()
        )
        
        print(f"🔑 Public key loaded from: {filename}")
    
    def encrypt(self, plaintext):
        if self.public_key is None:
            raise ValueError("No public key available. Generate or load keys first.")
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def decrypt(self, ciphertext_b64):
        if self.private_key is None:
            raise ValueError("No private key available. Load private key first.")
        
        ciphertext = base64.b64decode(ciphertext_b64)
        
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext.decode('utf-8')
    
    def sign(self, message):
        if self.private_key is None:
            raise ValueError("No private key available. Load private key first.")
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify(self, message, signature_b64):
        if self.public_key is None:
            raise ValueError("No public key available. Load or generate keys first.")
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = base64.b64decode(signature_b64)
        
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def encrypt_large_data(self, data, chunk_size=190):
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        encrypted_chunks = []
        
        for i, chunk in enumerate(chunks):
            encrypted = self.encrypt(chunk)
            encrypted_chunks.append(encrypted)
            print(f"📦 Encrypted chunk {i+1}/{len(chunks)}")
        
        return encrypted_chunks
    
    def decrypt_large_data(self, encrypted_chunks):
        decrypted_parts = []
        
        for i, chunk in enumerate(encrypted_chunks):
            decrypted = self.decrypt(chunk)
            decrypted_parts.append(decrypted)
            print(f"🔓 Decrypted chunk {i+1}/{len(encrypted_chunks)}")
        
        return ''.join(decrypted_parts)
    
    def get_public_key_pem(self):
        if self.public_key is None:
            raise ValueError("No public key available")
        
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def get_key_info(self):
        info = {
            'key_size': self.key_size,
            'has_private_key': self.private_key is not None,
            'has_public_key': self.public_key is not None
        }
        
        if self.public_key:
            info['public_key_size'] = self.public_key.key_size
        
        return info


def demo_basic_encryption():
    print("\n" + "="*60)
    print("📝 DEMO 1: Basic Encryption/Decryption")
    print("="*60)
    
    crypto = AsymmetricCrypto(key_size=2048)
    crypto.generate_key_pair()
    
    message = "Hello, this is a secret message! 🔐"
    print(f"\n📄 Original message: {message}")
    
    encrypted = crypto.encrypt(message)
    print(f"\n🔒 Encrypted (base64): {encrypted[:50]}...")
    
    decrypted = crypto.decrypt(encrypted)
    print(f"\n🔓 Decrypted message: {decrypted}")
    
    print(f"\n✅ Match: {message == decrypted}")


def demo_digital_signature():
    print("\n" + "="*60)
    print("✍️  DEMO 2: Digital Signatures")
    print("="*60)
    
    crypto = AsymmetricCrypto()
    crypto.generate_key_pair()
    
    document = "I agree to the terms and conditions."
    print(f"\n📄 Document: {document}")
    
    signature = crypto.sign(document)
    print(f"\n✍️  Signature (base64): {signature[:50]}...")
    
    is_valid = crypto.verify(document, signature)
    print(f"\n✅ Signature valid: {is_valid}")
    
    tampered = "I DO NOT agree to the terms and conditions."
    is_valid_tampered = crypto.verify(tampered, signature)
    print(f"\n❌ Tampered document valid: {is_valid_tampered}")


def demo_key_persistence():
    print("\n" + "="*60)
    print("💾 DEMO 3: Key Persistence")
    print("="*60)
    
    crypto1 = AsymmetricCrypto()
    crypto1.generate_key_pair()
    
    crypto1.save_private_key('private_key.pem', password='MySecurePassword123')
    crypto1.save_public_key('public_key.pem')
    
    message = "This message survives between sessions!"
    encrypted = crypto1.encrypt(message)
    print(f"\n🔒 Encrypted message: {encrypted[:50]}...")
    
    crypto2 = AsymmetricCrypto()
    crypto2.load_private_key('private_key.pem', password='MySecurePassword123')
    
    decrypted = crypto2.decrypt(encrypted)
    print(f"\n🔓 Decrypted message: {decrypted}")
    
    print(f"\n✅ Cross-instance decryption successful!")
    
    os.remove('private_key.pem')
    os.remove('public_key.pem')


def demo_large_data():
    print("\n" + "="*60)
    print("📚 DEMO 4: Large Data Encryption")
    print("="*60)
    
    crypto = AsymmetricCrypto()
    crypto.generate_key_pair()
    
    large_message = "This is a very long message. " * 50
    print(f"\n📄 Message length: {len(large_message)} bytes")
    
    encrypted_chunks = crypto.encrypt_large_data(large_message)
    print(f"\n📦 Total chunks: {len(encrypted_chunks)}")
    
    decrypted = crypto.decrypt_large_data(encrypted_chunks)
    print(f"\n✅ Decrypted length: {len(decrypted)} bytes")
    print(f"✅ Match: {large_message == decrypted}")


def demo_secure_communication():
    print("\n" + "="*60)
    print("🔐 DEMO 5: Secure Communication (Alice & Bob)")
    print("="*60)
    
    alice = AsymmetricCrypto()
    alice.generate_key_pair()
    alice.save_public_key('alice_public.pem')
    print("\n👩 Alice: Keys generated and public key shared")
    
    bob = AsymmetricCrypto()
    bob.generate_key_pair()
    bob.save_public_key('bob_public.pem')
    print("👨 Bob: Keys generated and public key shared")
    
    bob.load_public_key('alice_public.pem')
    message_to_alice = "Hey Alice, let's meet at 3 PM! 🤝"
    encrypted_for_alice = bob.encrypt(message_to_alice)
    print(f"\n👨 Bob → 👩 Alice: Encrypted message sent")
    
    decrypted_by_alice = alice.decrypt(encrypted_for_alice)
    print(f"👩 Alice received: '{decrypted_by_alice}'")
    
    alice_response = "Sounds good! See you then. 👍"
    alice_signature = alice.sign(alice_response)
    print(f"\n👩 Alice → 👨 Bob: Signed message")
    
    bob.load_public_key('alice_public.pem')
    is_authentic = bob.verify(alice_response, alice_signature)
    print(f"👨 Bob verified: {'✅ Authentic' if is_authentic else '❌ Forged'}")
    
    os.remove('alice_public.pem')
    os.remove('bob_public.pem')


def interactive_menu():
    crypto = AsymmetricCrypto()
    
    while True:
        print("\n" + "="*60)
        print("🔐 ASYMMETRIC CRYPTOGRAPHY MENU")
        print("="*60)
        print("1. Generate new key pair")
        print("2. Encrypt message")
        print("3. Decrypt message")
        print("4. Sign message")
        print("5. Verify signature")
        print("6. Save keys to file")
        print("7. Load keys from file")
        print("8. View key info")
        print("9. Run all demos")
        print("0. Exit")
        print("="*60)
        
        choice = input("\n👉 Choose option: ").strip()
        
        if choice == '1':
            key_size = input("Enter key size (2048/3072/4096) [2048]: ").strip() or '2048'
            crypto = AsymmetricCrypto(key_size=int(key_size))
            crypto.generate_key_pair()
            
        elif choice == '2':
            if crypto.public_key is None:
                print("❌ No keys available. Generate keys first!")
                continue
            message = input("Enter message to encrypt: ")
            try:
                encrypted = crypto.encrypt(message)
                print(f"\n🔒 Encrypted: {encrypted}")
            except Exception as e:
                print(f"❌ Error: {e}")
                
        elif choice == '3':
            if crypto.private_key is None:
                print("❌ No private key available. Load private key first!")
                continue
            ciphertext = input("Enter encrypted message (base64): ")
            try:
                decrypted = crypto.decrypt(ciphertext)
                print(f"\n🔓 Decrypted: {decrypted}")
            except Exception as e:
                print(f"❌ Error: {e}")
                
        elif choice == '4':
            if crypto.private_key is None:
                print("❌ No private key available. Generate keys first!")
                continue
            message = input("Enter message to sign: ")
            try:
                signature = crypto.sign(message)
                print(f"\n✍️  Signature: {signature}")
            except Exception as e:
                print(f"❌ Error: {e}")
                
        elif choice == '5':
            if crypto.public_key is None:
                print("❌ No public key available. Load public key first!")
                continue
            message = input("Enter original message: ")
            signature = input("Enter signature (base64): ")
            try:
                is_valid = crypto.verify(message, signature)
                print(f"\n{'✅ Valid signature!' if is_valid else '❌ Invalid signature!'}")
            except Exception as e:
                print(f"❌ Error: {e}")
                
        elif choice == '6':
            if crypto.private_key is None:
                print("❌ No keys to save. Generate keys first!")
                continue
            priv_file = input("Private key filename [private_key.pem]: ").strip() or 'private_key.pem'
            pub_file = input("Public key filename [public_key.pem]: ").strip() or 'public_key.pem'
            password = input("Password for private key (leave empty for none): ").strip() or None
            try:
                crypto.save_private_key(priv_file, password)
                crypto.save_public_key(pub_file)
            except Exception as e:
                print(f"❌ Error: {e}")
                
        elif choice == '7':
            key_type = input("Load (1) Private key or (2) Public key? ").strip()
            filename = input("Enter filename: ").strip()
            try:
                if key_type == '1':
                    password = input("Enter password (if encrypted): ").strip() or None
                    crypto.load_private_key(filename, password)
                else:
                    crypto.load_public_key(filename)
            except Exception as e:
                print(f"❌ Error: {e}")
                
        elif choice == '8':
            info = crypto.get_key_info()
            print("\n📊 Key Information:")
            print(f"  • Key size: {info['key_size']} bits")
            print(f"  • Has private key: {'✅' if info['has_private_key'] else '❌'}")
            print(f"  • Has public key: {'✅' if info['has_public_key'] else '❌'}")
            
        elif choice == '9':
            demo_basic_encryption()
            demo_digital_signature()
            demo_key_persistence()
            demo_large_data()
            demo_secure_communication()
            
        elif choice == '0':
            print("\n👋 Goodbye!")
            break
        else:
            print("❌ Invalid option!")


if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║         🔐 ASYMMETRIC CRYPTOGRAPHY SYSTEM 🔐            ║
    ║                                                          ║
    ║  Features:                                               ║
    ║    • RSA-2048/3072/4096 encryption                      ║
    ║    • Digital signatures (PSS)                           ║
    ║    • Key generation & persistence                       ║
    ║    • Large data encryption (chunked)                    ║
    ║    • Secure key storage (password-protected)            ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    mode = input("Choose mode: (1) Interactive Menu, (2) Run Demos, (3) Exit: ").strip()
    
    if mode == '1':
        interactive_menu()
    elif mode == '2':
        demo_basic_encryption()
        demo_digital_signature()
        demo_key_persistence()
        demo_large_data()
        demo_secure_communication()
        print("\n✅ All demos completed!")
    else:
        print("👋 Goodbye!")
