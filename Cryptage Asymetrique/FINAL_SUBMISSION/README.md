# SYSTÈME DE CHIFFREMENT ASYMÉTRIQUE RSA
## Rapport de Projet - Cryptographie

---

## 📋 Structure du Dossier

```
FINAL_SUBMISSION/
├── presentation/
│   ├── Cryptage_Asymetrique.pdf          ← RAPPORT COMPLET (À LIRE D'ABORD!)
│   └── Cryptage_Asymetrique.tex          (Source LaTeX)
│
├── sources/
│   ├── asymmetric_crypto.py              ← Code principal (pas de commentaires)
│   └── tutorial.py                       ← Tutoriel interactif (pas de commentaires)
│
└── documentation/
    └── requirements.txt                  ← Dépendances Python
```

---

## 📝 Contenu du Rapport PDF

Le fichier **Cryptage_Asymetrique.pdf** contient :

1. **Introduction** - Motivation et objectifs du projet
2. **Fondamentaux** - Théorie de la cryptographie asymétrique
3. **Architecture** - Structure et design du système
4. **Implémentation** - Code détaillé avec explications
5. **Utilisation** - Comment utiliser le système
6. **Cas d'Usage** - Applications pratiques
7. **Propriétés de Sécurité** - Garanties cryptographiques
8. **Résultats** - Tests et observations
9. **Conclusion** - Résumé et perspectives

---

## 🚀 Installation et Exécution Rapide

### 1. Installer les dépendances

```bash
pip install -r documentation/requirements.txt
```

**Requirement :**
- `cryptography>=41.0.0`

### 2. Exécuter le tutoriel interactif

```bash
python sources/tutorial.py
```

**Ce tutoriel :**
- Explique la théorie cryptographique
- Démontre chaque concept pas à pas
- Montre du code en exécution
- Inclut une simulation Alice & Bob

**Durée :** ~5 minutes (pausable entre les étapes)

### 3. Utiliser le menu interactif

```bash
python sources/asymmetric_crypto.py
```

**Options du menu :**
1. Générer une nouvelle paire de clés
2. Chiffrer un message
3. Déchiffrer un message
4. Signer un message
5. Vérifier une signature
6. Sauvegarder les clés
7. Charger les clés depuis fichier
8. Voir les informations des clés
9. Exécuter tous les 5 démonstrations
0. Quitter

---

## 📖 Exemple d'Utilisation

```python
from sources.asymmetric_crypto import AsymmetricCrypto

# 1. Créer un système de crypto
crypto = AsymmetricCrypto(key_size=2048)

# 2. Générer une paire de clés
crypto.generate_key_pair()

# 3. Chiffrer un message
message = "Message secret"
encrypted = crypto.encrypt(message)
print(f"Chiffré: {encrypted}")

# 4. Déchiffrer
decrypted = crypto.decrypt(encrypted)
print(f"Déchiffré: {decrypted}")  # Affiche "Message secret"

# 5. Signer un document
document = "Je suis d'accord"
signature = crypto.sign(document)

# 6. Vérifier la signature
is_valid = crypto.verify(document, signature)
print(f"Signature valide: {is_valid}")  # Affiche True

# 7. Sauvegarder les clés
crypto.save_private_key('ma_clé.pem', password='secure')
crypto.save_public_key('ma_clé_pub.pem')

# 8. Charger les clés plus tard
crypto2 = AsymmetricCrypto()
crypto2.load_private_key('ma_clé.pem', password='secure')
```

---

## 🔐 Fonctionnalités Principales

### Classe `AsymmetricCrypto`

#### Génération de Clés
```python
crypto.generate_key_pair()  # Génère RSA-2048 par défaut
crypto = AsymmetricCrypto(key_size=4096)  # Ou RSA-4096
```

#### Chiffrement
```python
ciphertext = crypto.encrypt("Message secret")  # Retourne base64
plaintext = crypto.decrypt(ciphertext)         # Retourne le message
```

#### Signatures Numériques
```python
signature = crypto.sign("Document")            # Retourne base64
is_valid = crypto.verify("Document", signature)  # True ou False
```

#### Gestion des Clés
```python
# Sauvegarder
crypto.save_private_key('key.pem', password='pwd')
crypto.save_public_key('key.pub')

# Charger
crypto.load_private_key('key.pem', password='pwd')
crypto.load_public_key('key.pub')
```

#### Grandes Données
```python
large_data = "Message très long..."
chunks = crypto.encrypt_large_data(large_data)  # Chunk RSA-2048 = 190 octets
result = crypto.decrypt_large_data(chunks)
```

---

## 📊 Concepts Clés Expliqués

### RSA (Rivest-Shamir-Adleman)

**Paire de Clés :**
- **Clé Publique** : Pour chiffrer (partage librement)
- **Clé Privée** : Pour déchiffrer (garde secrète)

**Propriétés :**
- Basé sur la factorisation de grands nombres premiers
- Mathématiquement impossible à casser (brute force nécessite des millénaires)
- Asymétrique : opérations différentes avec clés différentes

### RSA-OAEP (Optimal Asymmetric Encryption Padding)

**Avantages :**
- Chaque chiffrement est aléatoire (même message = ciphertext différent)
- Protège contre l'analyse de patterns
- Plus sûr que RSA brut

### Signatures Numériques

**Processus :**
1. Signer : hash(message) ^ clé_privée
2. Vérifier : signature ^ clé_publique = hash(message)

**Garanties :**
- ✅ **Authenticité** : Seul le propriétaire de la clé privée peut signer
- ✅ **Intégrité** : Impossible de modifier le message sans casser la signature
- ✅ **Non-répudiation** : Le signataire ne peut pas nier

---

## 🎯 Cas d'Usage Pratiques

### 1. Envoi de Messages Secrets

```
Alice         Bob
  ↓            ↑
  └─ [chiffré avec clé_pub(Bob)] ─→
```

### 2. Authentification

```
Alice signe: "Je suis Alice" → Signature
Bob vérifie signature avec clé_pub(Alice) → Authentique!
```

### 3. HTTPS/TLS (Web Sécurisé)

- Certificat serveur contient clé publique
- Serveur signe avec clé privée
- Client vérifie avec certificat

### 4. Email Sécurisé (PGP/GPG)

- Chiffrer emails avec clé publique destinataire
- Signer emails avec votre clé privée

### 5. Blockchain (Bitcoin, Ethereum)

- Adresses = dérivées de clé publique
- Transactions = signées avec clé privée
- N'importe qui peut vérifier = trustless

---

## 🧪 Tests et Démonstrations

### Tutoriel Interactif (14 Étapes)

Le fichier `tutorial.py` guide l'utilisateur à travers :

1. Génération de clés RSA
2. Chiffrement et déchiffrement
3. Aléatoire d'encryption
4. Signatures numériques
5. Vérification et tampering
6. Sauvegarde/chargement de clés
7. Chiffrement inter-instance
8. Communication Alice & Bob

### Démonstrations Intégrées (5 Démos)

Le menu interactif inclut 5 démonstrations :

1. **demo_basic_encryption()** - Chiffrement basique
2. **demo_digital_signature()** - Signatures
3. **demo_key_persistence()** - Sauvegarde/chargement
4. **demo_large_data()** - Données volumineuses
5. **demo_secure_communication()** - Simulation Alice & Bob

---

## ⚙️ Configuration Système

### Tailles de Clé Recommandées

| Taille | Sécurité | Cas d'Usage |
|--------|----------|------------|
| 2048-bit | Bon | Utilisations générales jusqu'en 2030 |
| 3072-bit | Meilleur | Données sensibles à long terme |
| 4096-bit | Excellent | Sécurité maximale (plus lent) |

### Performance

- Génération 2048-bit : ~quelques secondes
- Chiffrement : ~quelques millisecondes
- Déchiffrement : Plus lent que chiffrement
- 4096-bit : ~10x plus lent que 2048-bit

---

## 📚 Fichiers Fournis

### `asymmetric_crypto.py` (Production-Ready)

**Classe AsymmetricCrypto** - Implémentation complète
- 12 méthodes principales
- 5 démonstrations incluses
- Menu interactif avec 9 options
- Gestion complète des erreurs
- Logging détaillé

**Caractéristiques :**
- ✅ Code propre sans commentaires (format de soumission)
- ✅ Entièrement documenté dans le rapport PDF
- ✅ Production-ready et sécurisé
- ✅ ~300 lignes de code

### `tutorial.py` (Éducatif)

**Tutoriel Interactif 14 Étapes**
- Explications pédagogiques
- Code en exécution
- Démonstrations pas à pas
- Simulation communicaton sécurisée

**Caractéristiques :**
- ✅ Interactif (pause entre les étapes)
- ✅ Explications progressives
- ✅ Sans commentaires (format de soumission)
- ✅ ~350 lignes

### `requirements.txt`

```
cryptography>=41.0.0
```

Unique dépendance externe.

---

## 🔒 Sécurité

### Ce qui est Sécurisé ✅

- **Chiffrement RSA-OAEP** : Standard de l'industrie
- **Signatures PSS** : Probabilistic Signature Scheme
- **Format PEM** : Standard reconnu internationalement
- **Clés protégeables par mot de passe**
- **Pas d'hardcoding de secrets**

### Recommandations de Sécurité 🔑

1. **Protégez votre clé privée** : Utilisez un mot de passe fort
2. **Partagez librement** : Distribuez votre clé publique
3. **Vérifiez les signatures** : Confirmez l'authenticité
4. **Mettez à jour** : Utilisez les dernières versions

---

## 🤝 Communication Sécurisée (Exemple)

### Scénario Alice & Bob

**ÉTAPE 1 : Échange de clés publiques**
```
Alice génère (priv_A, pub_A)
Bob génère (priv_B, pub_B)

Alice → Bob : pub_A
Bob → Alice : pub_B
```

**ÉTAPE 2 : Bob envoie message secret à Alice**
```
Bob charge pub_A
Message = "Rendez-vous à 3PM"
Encrypted = RSA_encrypt(Message, pub_A)
Bob → Alice : Encrypted (peut être intercepté!)
```

**ÉTAPE 3 : Alice déchiffre**
```
Alice utilise priv_A
Message = RSA_decrypt(Encrypted, priv_A) = "Rendez-vous à 3PM"
Seule Alice peut lire!
```

**ÉTAPE 4 : Alice signe une réponse**
```
Reply = "D'accord!"
Signature = Sign(Reply, priv_A)
Alice → Bob : Reply + Signature (message public + signature)
```

**ÉTAPE 5 : Bob vérifie**
```
Bob charge pub_A
is_valid = Verify(Reply, Signature, pub_A) = True
Bob sait que c'est réellement Alice!
```

---

## 🎓 Pour les Enseignants

### Utilisation Pédagogique

1. **Théorie** : Lire le rapport PDF (chapitres 2-3)
2. **Pratique** : Exécuter le tutoriel (`tutorial.py`)
3. **Expérimentation** : Utiliser le menu interactif
4. **Application** : Adapter le code pour d'autres usages

### Points de Discussion

- Pourquoi RSA est-il asymétrique?
- Pourquoi OAEP est-il meilleur que RSA brut?
- Quelle est la différence entre chiffrement et signature?
- Comment blockchain utilise-t-il RSA?
- Quels sont les enjeux de sécurité?

---

## 🆘 Dépannage

### Erreur : "Module 'cryptography' not found"

**Solution :**
```bash
pip install cryptography>=41.0.0
```

### Erreur : "No private key available"

**Solution :** Générez d'abord une paire de clés
```python
crypto = AsymmetricCrypto()
crypto.generate_key_pair()
```

### Le tutoriel n'avance pas

**Solution :** Appuyez sur ENTER pour continuer (pause entre les étapes)

---

## 📞 Support

Pour toute question sur le code ou la théorie, consultez :
- **Rapport PDF** : Explication détaillée de chaque concept
- **Docstrings** : (dans le code source original, avant commentaires)
- **Code** : Clair et lisible

---

## ✨ Résumé

Ce projet fournit une **implémentation complète et pédagogique** de la cryptographie asymétrique RSA, incluant :

✅ Classe `AsymmetricCrypto` production-ready
✅ Chiffrement et déchiffrement (RSA-OAEP)
✅ Signatures numériques (PSS)
✅ Gestion sécurisée des clés
✅ Tutoriel interactif 14 étapes
✅ Menu avec 5 démonstrations
✅ Rapport complet (rapport PDF, ~20 pages)
✅ Code propre sans commentaires

**Prêt pour la soumission!** 🎉

---

**Date** : November 17, 2025
**Langage** : Python 3.8+
**Dépendances** : cryptography >= 41.0.0
