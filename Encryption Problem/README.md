<div align="center">

# 🔐 CryptoVault

### A production-grade encryption & decryption toolkit for Python

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#license)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-orange.svg)](#security-properties)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#dependencies)

Secure your text, files, and secrets with military-grade cryptography — right from the command line.

</div>

---

## 📖 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
  - [Key Management](#1-key-management)
  - [Symmetric Encryption](#2-symmetric-encryption-key-based)
  - [Password Mode](#3-password-mode-no-key-files)
  - [Asymmetric Encryption](#4-asymmetric-encryption-x25519)
  - [Encrypted Vault](#5-encrypted-vault)
  - [Additional Authenticated Data](#6-additional-authenticated-data-aad)
- [Architecture & Wire Formats](#architecture--wire-formats)
- [File Locations](#file-locations)
- [Security Properties](#security-properties)
- [Dependencies](#dependencies)
- [Testing](#testing)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Overview

Sensitive information — passwords, personal data, confidential messages — needs protection from unauthorized access. **CryptoVault** is a self-contained Python tool that makes strong, authenticated encryption accessible from a single script, with no external services or infrastructure required.

**Use it to:**

| Use Case | Description |
|---|---|
| 🔒 Secure storage | Protect sensitive text data at rest |
| 📚 Learning | Understand how cryptographic keys and algorithms work in practice |
| 🗂️ Document protection | Safeguard notes, passwords, and confidential files |
| 🛡️ Cybersecurity fundamentals | A hands-on project for confidentiality principles |
| 💬 Secure communication | Exchange encrypted messages between trusted parties |

---

## Features

| Feature | Description |
|---|---|
| **AES-256-GCM** | Authenticated encryption — tampering is detected immediately |
| **Multi-key keystore** | Generate, rotate, list, and revoke keys without losing access to old data |
| **Password mode** | Encrypt/decrypt with just a password — no key file needed |
| **Asymmetric (X25519)** | Forward-secret encryption using X25519 + HKDF |
| **Encrypted vault** | Labeled, HMAC-protected message store |
| **Streaming file I/O** | Encrypt files of any size — memory usage stays at 64 KB |
| **Cross-platform** | Works on Linux, macOS, and Windows (with optional `pywin32` ACL support) |
| **Interactive & CLI modes** | Menu-driven or command-line — your choice |
| **Progress bars** | `tqdm` integration for large file operations |
| **Memory cleanup** | Best-effort zeroing of key material after use |

---

## Quick Start

### 1. Install dependencies

```bash
pip install cryptography

# Optional, but recommended:
pip install tqdm pywin32
```

### 2. Save the script

Save the source code as `cryptovault.py` in your project directory.

### 3. Run it

```bash
# Generate your first encryption key
python cryptovault.py --generate

# Encrypt a message
python cryptovault.py --encrypt "Hello, this is secret!"

# Decrypt it
python cryptovault.py --decrypt "gAAAAAB..."

# Or launch the interactive menu
python cryptovault.py --interactive
```

---

## Command Reference

### 1. Key Management

```bash
# Generate a new encryption key (becomes active)
python cryptovault.py --generate
python cryptovault.py --generate "work laptop 2026"

# List all saved keys
python cryptovault.py --list-keys

# Rotate to a new key (old keys are kept for decrypting old data)
python cryptovault.py --rotate
python cryptovault.py --rotate "quarterly rotation Q3"

# Permanently remove a key (irreversible)
python cryptovault.py --revoke <key_id>
```

### 2. Symmetric Encryption (Key-Based)

```bash
# Encrypt a message
python cryptovault.py --encrypt "Secret message here"

# Decrypt a message
python cryptovault.py --decrypt "gAAAAABwv8Y..."

# Pipe mode (read from stdin)
cat secret.txt | python cryptovault.py --stdin --encrypt
echo "gAAAAAB..." | python cryptovault.py --stdin --decrypt

# Encrypt a file (any size, streamed)
python cryptovault.py --encrypt-file document.pdf

# Decrypt a file
python cryptovault.py --decrypt-file document.pdf.crypt
```

### 3. Password Mode (No Key Files)

```bash
# Encrypt — only need to remember the password
python cryptovault.py --encrypt-pw "My diary entry"
# You'll be prompted for a password.
# The output includes the salt + iteration count — nothing is stored on disk.

# Decrypt
python cryptovault.py --decrypt-pw "gAAAAAB..."
```

### 4. Asymmetric Encryption (X25519)

```bash
# Generate your key pair
python cryptovault.py --keygen-asym

# Show your public key (share with anyone who wants to message you securely)
python cryptovault.py --pubkey

# Encrypt a message using someone else's public key
python cryptovault.py --encrypt-asym "base64_public_key_here" "Secret for you"

# Decrypt a message sent to you
python cryptovault.py --decrypt-asym "gAAAAAB..."
```

### 5. Encrypted Vault

```bash
# Store an encrypted message under a label
python cryptovault.py --vault-store "my_password" "correct horse battery staple"

# List all vault entries (labels only — content stays encrypted)
python cryptovault.py --vault-list

# Read and decrypt a vault entry
python cryptovault.py --vault-read "my_password"

# Delete a vault entry
python cryptovault.py --vault-del "old_entry"
```

### 6. Additional Authenticated Data (AAD)

```bash
# Bind context to ciphertext so it can't be swapped between uses
python cryptovault.py --aad "user_id_42" --encrypt "salary: 75000"
python cryptovault.py --aad "user_id_42" --decrypt "gAAAAAB..."
```

---

## Architecture & Wire Formats

**Symmetric mode**

```
[1 byte version] [8 byte key_id] [12 byte nonce] [AES-GCM ciphertext + 16 byte tag]
```
Base64-encoded for transport. Total overhead: **29 bytes** before base64 expansion.

**Password mode**

```
[1 byte version] [32 byte salt] [4 byte iterations] [12 byte nonce] [ciphertext + 16 byte tag]
```
Everything needed for decryption is self-contained in the output string.

**Asymmetric mode**

```
[32 byte ephemeral public key] [inner symmetric ciphertext]
```
The inner ciphertext uses the symmetric format above, with a one-time AES key derived via X25519 + HKDF.

---

## File Locations

All data is stored under `~/.cryptovault/`:

| File | Purpose |
|---|---|
| `~/.cryptovault/keys.json` | Multi-key keystore (encryption keys, base64-encoded) |
| `~/.cryptovault/vault.json` | Encrypted message vault, HMAC-protected |
| `~/.cryptovault/x25519_private.key` | Your X25519 private key |

> All files are created with `chmod 600` (owner-only access). On Windows, `pywin32` ACLs are applied automatically when available.

---

## Security Properties

| Property | Detail |
|---|---|
| **Encryption** | AES-256-GCM (NIST standard, 256-bit key) |
| **Key derivation** | PBKDF2-SHA256, 600,000 iterations |
| **Key exchange** | X25519 ECDH + HKDF-SHA256 |
| **Forward secrecy** | ✅ Yes — asymmetric mode uses ephemeral keys |
| **Integrity** | GCM authentication tag + HMAC-SHA256 vault signing |
| **Nonce** | 96-bit random, freshly generated for every encryption |
| **Memory hygiene** | Best-effort zeroing of key material via `ctypes` |

---

## Dependencies

| Library | Required | Purpose |
|---|:---:|---|
| `cryptography` | ✅ Yes | All cryptographic operations |
| `tqdm` | ⬜ No | Progress bars for file operations |
| `pywin32` | ⬜ No | Windows file permission ACLs |

---

## Testing

```bash
# Quick smoke test
python cryptovault.py --generate
RESULT=$(python cryptovault.py --encrypt "test message")
DECRYPTED=$(python cryptovault.py --decrypt "$RESULT")
[ "$DECRYPTED" = "test message" ] && echo "PASS" || echo "FAIL"

# Password mode test
RESULT=$(python cryptovault.py --encrypt-pw "hello" <<< "test123" 2>/dev/null)
# ^ won't work directly due to interactive password prompt — use --interactive instead
```

---

## Known Limitations

- **Memory wiping is best-effort** — Python's `bytes` are immutable; `ctypes` is used to attempt zeroing, but this isn't guaranteed by the language spec.
- **No hardware security module (HSM)** — keys are stored on disk, not in a TPM or secure enclave.
- **No certificate infrastructure** — asymmetric mode uses raw public keys, not X.509 certificates.
- **Birthday bound** — with random 96-bit nonces, after ~2⁴⁸ encryptions under the same key there's a 50% chance of nonce collision. Not a practical concern for typical usage.

---

## License

Released under the **MIT License**. See [LICENSE](LICENSE) for details.
