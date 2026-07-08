#!/usr/bin/env python3
"""
Encryption / Decryption Tool - Problem Statement & Practical Use

Problem Statement:
Sensitive information such as passwords, personal data, and confidential messages
must be protected from unauthorized access. This project focuses on creating a Python
tool capable of encrypting and decrypting text using cryptographic algorithms. The tool
allows generating a secure encryption key, encrypting messages, and decrypting them
back using the saved key.

Practical Use:
- Secure storage of sensitive text data
- Learning how cryptographic keys and encryption algorithms work
- Protecting notes, passwords, and confidential documents
- A foundational cybersecurity project to understand confidentiality principles
- Useful for secure communication between trusted parties

Ethical Note:
Use encryption ethically and responsibly. Always keep your encryption keys safe.
Losing the key means you cannot decrypt your data.
"""

import os
import sys
import json
import hmac
import hashlib
import base64
import struct
import getpass
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, Tuple, List, Dict, Any

# ── External Dependencies ──────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("[!] Missing required library. Install it with:")
    print("    pip install cryptography")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

try:
    import win32security
    import win32api
    _WIN32 = True
except ImportError:
    _WIN32 = False


# ════════════════════════════════════════════════════════════
#  CONFIGURATION & CONSTANTS
# ════════════════════════════════════════════════════════════

CONFIG_DIR = Path.home() / ".cryptovault"
CONFIG_DIR.mkdir(exist_ok=True)

KEYSTORE_PATH = CONFIG_DIR / "keys.json"
VAULT_PATH    = CONFIG_DIR / "vault.json"
KEYPAIR_PATH  = CONFIG_DIR / "x25519_private.key"

# AES-256-GCM parameters
IV_SIZE        = 12     # 96-bit nonce (NIST standard for GCM)
SALT_SIZE      = 32     # 256-bit salt for PBKDF2
KEY_ID_BYTES   = 8      # 64-bit random key identifier
PBKDF2_ITERS   = 600_000  # OWASP 2023 recommended minimum
CHUNK_SIZE     = 64 * 1024  # 64 KB streaming chunks
FORMAT_VERSION = 1      # Wire format version


# ════════════════════════════════════════════════════════════
#  CUSTOM EXCEPTIONS
# ════════════════════════════════════════════════════════════

class CryptoError(Exception):
    """Base exception for all crypto operations in this tool."""
    pass

class KeyNotFound(CryptoError):
    """Raised when a requested key doesn't exist in the keystore."""
    pass

class DecryptFailed(CryptoError):
    """Raised when decryption fails — wrong key, tampered data, or corruption."""
    pass

class VaultTampered(CryptoError):
    """Raised when the vault file's HMAC integrity check fails."""
    pass


# ════════════════════════════════════════════════════════════
#  SECURE MEMORY CLEANUP
# ════════════════════════════════════════════════════════════
# Python's immutable 'bytes' can't be reliably zeroed, so we
# convert keys to 'bytearray' during sensitive operations and
# zero those. This is defense-in-depth — the key material may
# still linger in memory after GC.

def _secure_bytearray(data: bytes) -> bytearray:
    """
    Convert bytes to a mutable bytearray so we can zero it later.
    The caller MUST call _zero_bytearray() when done.
    """
    return bytearray(data)


def _zero_bytearray(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros, then release it."""
    for i in range(len(buf)):
        buf[i] = 0


def _zero_bytes_via_buffer(b: bytes) -> None:
    """
    Best-effort attempt to zero a bytes object using its internal buffer.
    This is CPython-specific and may fail silently. Not guaranteed.
    """
    try:
        # Modern CPython: use Py_buffer API via ctypes
        import ctypes
        class Py_buffer(ctypes.Structure):
            _fields_ = [
                ('buf', ctypes.c_void_p),
                ('obj', ctypes.py_object),
                ('len', ctypes.c_ssize_t),
                ('itemsize', ctypes.c_ssize_t),
                ('readonly', ctypes.c_int),
                ('ndim', ctypes.c_int),
                ('format', ctypes.c_char_p),
                ('shape', ctypes.POINTER(ctypes.c_ssize_t)),
                ('strides', ctypes.POINTER(ctypes.c_ssize_t)),
                ('suboffsets', ctypes.POINTER(ctypes.c_ssize_t)),
                ('internal', ctypes.c_void_p),
            ]
        buf = Py_buffer()
        # PyObject_GetBuffer with PyBUF_SIMPLE (0) requests the raw buffer
        ret = ctypes.pythonapi.PyObject_GetBuffer(
            ctypes.py_object(b),
            ctypes.byref(buf),
            0  # PyBUF_SIMPLE
        )
        if ret == 0:
            ctypes.memset(buf.buf, 0, buf.len)
            ctypes.pythonapi.PyBuffer_Release(ctypes.byref(buf))
    except Exception:
        pass  # couldn't wipe — key will be GC'd eventually


# ════════════════════════════════════════════════════════════
#  KEY MANAGEMENT — Multi-Key Store with Rotation
# ════════════════════════════════════════════════════════════
# The tool allows generating a secure encryption key, encrypting
# messages, and decrypting them back using the saved key.
# Multiple keys are supported so you can rotate without losing
# access to old encrypted data.

@dataclass
class KeyEntry:
    """Represents a single encryption key with metadata."""
    key_id: str
    key_bytes: bytes
    created: str
    active: bool = True
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.key_id,
            "key": base64.b64encode(self.key_bytes).decode(),
            "created": self.created,
            "active": self.active,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KeyEntry":
        return cls(
            key_id=d["id"],
            key_bytes=base64.b64decode(d["key"]),
            created=d["created"],
            active=d.get("active", True),
            note=d.get("note", ""),
        )


class KeyStore:
    """
    Manages encryption keys on disk.
    Generates secure AES-256 keys, saves them with restricted permissions,
    and supports rotation, revocation, and listing.
    """

    def __init__(self, path: Path = KEYSTORE_PATH):
        self.path = path
        self.keys: Dict[str, KeyEntry] = {}
        self.active_id: Optional[str] = None
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self.keys = {}
            self.active_id = None
            return
        try:
            raw = json.loads(self.path.read_text())
            self.keys = {}
            for e in raw.get("keys", []):
                entry = KeyEntry.from_dict(e)
                self.keys[entry.key_id] = entry
                if entry.active:
                    self.active_id = entry.key_id
        except (json.JSONDecodeError, KeyError, ValueError) as ex:
            raise CryptoError(f"Keystore file corrupted: {ex}")

    def _save(self) -> None:
        data = {"version": FORMAT_VERSION, "keys": [e.to_dict() for e in self.keys.values()]}
        self.path.write_text(json.dumps(data, indent=2))
        self._lockdown(self.path)

    def generate(self, note: str = "") -> KeyEntry:
        """
        Generate a secure encryption key using cryptographically strong randomness.
        The new key automatically becomes the active key for future encryptions.
        """
        raw = AESGCM.generate_key(bit_length=256)  # 32 bytes
        kid = base64.b16encode(os.urandom(KEY_ID_BYTES)).decode().lower()
        entry = KeyEntry(
            key_id=kid,
            key_bytes=raw,
            created=datetime.now(timezone.utc).isoformat(),
            active=True,
            note=note,
        )
        # Deactivate all other keys
        for k in self.keys.values():
            k.active = False
        self.keys[kid] = entry
        self.active_id = kid
        self._save()
        print(f"[+] Generated new encryption key: {entry.key_id}")
        return entry

    def active(self) -> KeyEntry:
        """Return the currently active encryption key."""
        if self.active_id and self.active_id in self.keys:
            return self.keys[self.active_id]
        if self.keys:
            # Fallback to first available key
            self.active_id = list(self.keys.keys())[0]
            return self.keys[self.active_id]
        raise KeyNotFound(
            "No encryption keys found. Generate one with --generate first."
        )

    def get(self, kid: str) -> KeyEntry:
        """Look up a key by its unique identifier."""
        if kid not in self.keys:
            raise KeyNotFound(f"Key '{kid}' not found in keystore.")
        return self.keys[kid]

    def list_all(self) -> List[dict]:
        """List all keys with metadata. Key material is NOT exposed."""
        return [{
            "id": e.key_id,
            "created": e.created,
            "active": e.active,
            "note": e.note,
        } for e in self.keys.values()]

    def rotate(self, note: str = "") -> KeyEntry:
        """Generate a new active key while keeping old keys for decryption."""
        print("[+] Rotating to new encryption key...")
        return self.generate(note=note)

    def revoke(self, kid: str) -> None:
        """Permanently remove a key. Only do this if nothing is encrypted with it."""
        if kid not in self.keys:
            raise KeyNotFound(f"Key '{kid}' not found.")
        del self.keys[kid]
        if self.active_id == kid:
            self.active_id = next(iter(self.keys.keys())) if self.keys else None
        self._save()
        print(f"[+] Key '{kid}' revoked and removed from keystore.")

    @staticmethod
    def _lockdown(path: Path) -> None:
        """Restrict file to owner-only access. Works on Linux/macOS/Windows."""
        try:
            os.chmod(path, 0o600)
        except NotImplementedError:
            pass
        if _WIN32:
            try:
                sid = win32security.GetBinarySid(
                    win32security.ConvertSidToStringSid(
                        win32security.GetTokenInformation(
                            win32api.OpenProcessToken(
                                win32api.GetCurrentProcess(), 0x0008
                            ),
                            win32security.TokenUser
                        )[0]
                    )
                )
                sd = win32security.SECURITY_DESCRIPTOR()
                sd.SetSecurityDescriptorOwner(sid, False)
                acl = win32security.ACL()
                acl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    0x10000000,  # GENERIC_ALL
                    sid,
                )
                sd.SetSecurityDescriptorDacl(True, acl, False)
                win32security.SetFileSecurity(
                    str(path),
                    win32security.DACL_SECURITY_INFORMATION,
                    sd,
                )
            except Exception:
                pass  # Best-effort on Windows


# ════════════════════════════════════════════════════════════
#  WIRE FORMAT PARSING
# ════════════════════════════════════════════════════════════
#
#  Header (21 bytes):
#    [1 byte version] [8 byte key_id] [12 byte nonce]
#
#  Full payload:
#    [header 21 bytes] [AES-GCM ciphertext + 16 byte tag]
#
#  We split parsing into two functions: one for the header only
#  (used when reading file headers) and one for the full payload
#  (used when decrypting in-memory messages).

HEADER_SIZE = 1 + KEY_ID_BYTES + IV_SIZE  # 21 bytes


def _pack_header(kid: str, nonce: bytes) -> bytes:
    """Build the 21-byte binary header for a ciphertext."""
    assert len(nonce) == IV_SIZE, f"nonce must be {IV_SIZE} bytes"
    return struct.pack("!B", FORMAT_VERSION) + bytes.fromhex(kid) + nonce


def _parse_header(data: bytes) -> Tuple[int, str, bytes]:
    """
    Parse ONLY the 21-byte header. Returns (version, key_id_hex, nonce).
    Raises DecryptFailed if the data is too short or version mismatches.
    This does NOT check for ciphertext — use _parse_full_payload for that.
    """
    if len(data) < HEADER_SIZE:
        raise DecryptFailed(
            f"Header too short: got {len(data)} bytes, need {HEADER_SIZE}."
        )
    version = struct.unpack("!B", data[:1])[0]
    if version != FORMAT_VERSION:
        raise DecryptFailed(
            f"Unknown format version {version}. "
            "Data may be from a different tool version."
        )
    kid = data[1:1+KEY_ID_BYTES].hex()
    nonce = data[1+KEY_ID_BYTES:HEADER_SIZE]
    return version, kid, nonce


def _parse_full_payload(data: bytes) -> Tuple[int, str, bytes, bytes]:
    """
    Parse a full ciphertext payload (header + ciphertext + GCM tag).
    Returns: (version, key_id_hex, nonce, remaining_ciphertext_and_tag)
    Raises DecryptFailed if data is too short.
    """
    if len(data) < HEADER_SIZE + 1:
        raise DecryptFailed(
            f"Data too short ({len(data)} bytes) to be a valid ciphertext. "
            "Minimum is 22 bytes (21 header + 1 byte ciphertext)."
        )
    version, kid, nonce = _parse_header(data)
    rest = data[HEADER_SIZE:]
    return version, kid, nonce, rest


# ════════════════════════════════════════════════════════════
#  CORE ENCRYPTION / DECRYPTION (AES-256-GCM)
# ════════════════════════════════════════════════════════════
#
# Benefits of AES-256-GCM:
#   - Authenticated encryption (tampering detected via auth tag)
#   - No padding (not vulnerable to padding oracle attacks)
#   - 256-bit key (quantum-safe for the foreseeable future)

def encrypt(plaintext: str, key: KeyEntry, aad: str = "") -> str:
    """
    Encrypt a message using AES-256-GCM.
    
    Additional Authenticated Data (AAD) is cryptographically bound to the
    ciphertext but not encrypted. It prevents ciphertext swapping between
    different contexts.
    
    Returns: base64-encoded string containing the header + ciphertext.
    """
    gcm = AESGCM(key.key_bytes)
    nonce = os.urandom(IV_SIZE)
    aad_bytes = aad.encode("utf-8") if aad else b""
    ct = gcm.encrypt(nonce, plaintext.encode("utf-8"), aad_bytes)
    payload = _pack_header(key.key_id, nonce) + ct
    return base64.b64encode(payload).decode()


def decrypt(ciphertext_b64: str, ks: KeyStore, aad: str = "") -> Tuple[str, str]:
    """
    Decrypt a base64-encoded ciphertext back to the original message.
    
    First tries the key identified in the ciphertext header.
    Falls back to all remaining keys if the header key fails.
    This ensures you can decrypt old data even after key rotation.
    
    Returns: (plaintext, key_id_used)
    """
    try:
        raw = base64.b64decode(ciphertext_b64)
    except Exception as ex:
        raise DecryptFailed(f"Invalid base64 encoding: {ex}")

    version, header_kid, nonce, ct_and_tag = _parse_full_payload(raw)
    aad_bytes = aad.encode("utf-8") if aad else b""

    # Build candidate key list: header key first, then all others
    candidates: List[KeyEntry] = []
    try:
        candidates.append(ks.get(header_kid))
    except KeyNotFound:
        pass
    for e in ks.keys.values():
        if e.key_id != header_kid:
            candidates.append(e)

    if not candidates:
        raise DecryptFailed("No encryption keys available to attempt decryption.")

    # Try each key. GCM's auth tag instantly rejects wrong keys.
    for entry in candidates:
        try:
            gcm = AESGCM(entry.key_bytes)
            plaintext = gcm.decrypt(nonce, ct_and_tag, aad_bytes)
            if entry.key_id != header_kid:
                print(
                    f"[!] Decrypted with key '{entry.key_id[:16]}...' "
                    f"(different from header key '{header_kid[:16]}...')"
                )
            return plaintext.decode("utf-8"), entry.key_id
        except InvalidTag:
            continue

    raise DecryptFailed(
        f"Decryption failed with all {len(candidates)} available key(s).\n"
        "The key used to encrypt this message may have been revoked, "
        "or the ciphertext was tampered with."
    )


# ════════════════════════════════════════════════════════════
#  STREAMING FILE ENCRYPTION / DECRYPTION
# ════════════════════════════════════════════════════════════
# Uses the low-level Cipher API to process files in 64KB chunks.
# Memory usage stays at ~64KB regardless of file size.

def encrypt_file(inpath: Path, key: KeyEntry, outpath: Optional[Path] = None) -> Path:
    """
    Encrypt a file using streaming AES-256-GCM. Handles files of any size.
    Output file format: [21-byte header] [encrypted chunks] [16-byte GCM tag]
    """
    if outpath is None:
        outpath = inpath.with_suffix(inpath.suffix + ".crypt")

    nonce = os.urandom(IV_SIZE)
    header = _pack_header(key.key_id, nonce)

    cipher = Cipher(algorithms.AES(key.key_bytes), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(b"")

    file_size = inpath.stat().st_size
    progress = tqdm(
        total=file_size, unit="B", unit_scale=True, desc="Encrypting"
    ) if tqdm else None

    with open(inpath, "rb") as fin, open(outpath, "wb") as fout:
        fout.write(header)
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            fout.write(encrypted_chunk)
            if progress:
                progress.update(len(chunk))

        encryptor.finalize()
        fout.write(encryptor.tag)

    if progress:
        progress.close()

    print(f"[+] File encrypted: {inpath.name} -> {outpath.name}")
    return outpath


def decrypt_file(inpath: Path, ks: KeyStore, outpath: Optional[Path] = None) -> Path:
    """
    Decrypt a file encrypted with encrypt_file().
    
    Reads the 21-byte header to identify the key and nonce, then decrypts
    the rest in 64KB chunks. Falls back to all keys if the header key fails.
    
    Memory usage is ~CHUNK_SIZE regardless of file size.
    """
    if outpath is None:
        if inpath.suffix == ".crypt":
            outpath = inpath.with_suffix("")
        else:
            outpath = inpath.with_name(inpath.stem + ".decrypted")

    # Read header (21 bytes) and the rest separately
    with open(inpath, "rb") as f:
        header_bytes = f.read(HEADER_SIZE)
        if len(header_bytes) < HEADER_SIZE:
            raise DecryptFailed(
                f"File too small: got {len(header_bytes)} bytes, "
                f"expected at least {HEADER_SIZE} for header."
            )
        # Parse JUST the header — _parse_header does NOT require ciphertext
        version, kid, nonce = _parse_header(header_bytes)
        # Read the encrypted data (ciphertext + 16-byte GCM tag)
        rest = f.read()

    if len(rest) < 17:
        raise DecryptFailed(
            f"File too small: only {len(rest)} bytes of ciphertext data, "
            "need at least 1 byte of ciphertext + 16-byte GCM tag."
        )

    ct = rest[:-16]
    tag = rest[-16:]

    # Build candidate key list (same fallback logic as decrypt())
    candidates: List[KeyEntry] = []
    try:
        candidates.append(ks.get(kid))
    except KeyNotFound:
        pass
    for e in ks.keys.values():
        if e.key_id != kid:
            candidates.append(e)

    if not candidates:
        raise DecryptFailed("No keys available to attempt file decryption.")

    last_err: Optional[Exception] = None
    for entry in candidates:
        try:
            cipher = Cipher(
                algorithms.AES(entry.key_bytes), modes.GCM(nonce, tag)
            )
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(b"")

            progress = tqdm(
                total=len(ct), unit="B", unit_scale=True, desc="Decrypting"
            ) if tqdm else None

            with open(outpath, "wb") as fout:
                offset = 0
                while offset < len(ct):
                    chunk = ct[offset:offset + CHUNK_SIZE]
                    decrypted_chunk = decryptor.update(chunk)
                    fout.write(decrypted_chunk)
                    offset += len(chunk)
                    if progress:
                        progress.update(len(chunk))
                decryptor.finalize()

            if progress:
                progress.close()

            if entry.key_id != kid:
                print(
                    f"[!] Decrypted using key '{entry.key_id[:16]}...' "
                    f"(different from header key '{kid[:16]}...')"
                )
            print(f"[+] File decrypted: {inpath.name} -> {outpath.name}")
            return outpath
        except InvalidTag as e:
            last_err = e
            continue

    raise DecryptFailed(
        f"File decryption failed with all {len(candidates)} available key(s)."
    )


# ════════════════════════════════════════════════════════════
#  PASSWORD-BASED ENCRYPTION (No Key File Needed)
# ════════════════════════════════════════════════════════════
# Losing the key means you cannot decrypt your data.
# In password mode, the encryption key is derived from your password
# each time using PBKDF2-SHA256. The salt and iteration count are
# embedded in the output string — nothing is stored on disk.
#
# Wire format: [ver:1][salt:32][iters:4][nonce:12][ciphertext][tag:16]

def encrypt_with_password(plaintext: str, password: str) -> str:
    """
    Encrypt a message using a password. No key file is needed.
    The salt and PBKDF2 iteration count are embedded in the output.
    """
    salt = os.urandom(SALT_SIZE)

    # Derive a 32-byte AES key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    key = kdf.derive(password.encode("utf-8"))

    nonce = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(b"")
    ct = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag

    # Wipe the derived key from memory
    _zero_bytes_via_buffer(key)

    payload = (
        struct.pack("!B", FORMAT_VERSION) +
        salt +
        struct.pack("!I", PBKDF2_ITERS) +
        nonce +
        ct +
        tag
    )
    return base64.b64encode(payload).decode()


def decrypt_with_password(ciphertext_b64: str, password: str) -> str:
    """
    Decrypt a message encrypted with encrypt_with_password().
    Extracts salt and iterations from the ciphertext, re-derives the key,
    and decrypts. Losing the key means you cannot decrypt your data.
    """
    try:
        raw = base64.b64decode(ciphertext_b64)
    except Exception as ex:
        raise DecryptFailed(f"Invalid base64 encoding: {ex}")

    # Minimum length: version(1) + salt(32) + iters(4) + nonce(12) + min_ct(1) + tag(16) = 66
    if len(raw) < 66:
        raise DecryptFailed(
            "Ciphertext too short to be valid password-encrypted data."
        )

    offset = 0
    version = struct.unpack("!B", raw[offset:offset+1])[0]
    offset += 1
    if version != FORMAT_VERSION:
        raise DecryptFailed(f"Unknown format version {version}.")
    salt = raw[offset:offset+SALT_SIZE]
    offset += SALT_SIZE
    iterations = struct.unpack("!I", raw[offset:offset+4])[0]
    offset += 4
    nonce = raw[offset:offset+IV_SIZE]
    offset += IV_SIZE
    ct = raw[offset:-16]
    tag = raw[-16:]

    # Re-derive the key using the stored salt and iteration count
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode("utf-8"))

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(b"")
        plaintext = decryptor.update(ct) + decryptor.finalize()
        return plaintext.decode("utf-8")
    except InvalidTag:
        raise DecryptFailed(
            "Wrong password or tampered ciphertext.\n"
            "Losing the key means you cannot decrypt your data."
        )
    finally:
        _zero_bytes_via_buffer(key)


# ════════════════════════════════════════════════════════════
#  ASYMMETRIC ENCRYPTION (X25519 + HKDF)
# ════════════════════════════════════════════════════════════
# Useful for secure communication between trusted parties.
#
# Flow:
#   1. Sender generates an ephemeral X25519 key pair
#   2. Sender does DH with recipient's public key → shared secret
#   3. HKDF derives an AES-256-GCM key from the shared secret
#   4. Sender encrypts the message and embeds the ephemeral public key
#   5. Sender discards the ephemeral private key (forward secrecy)
#   6. Recipient extracts the ephemeral public key, re-derives the secret

def _load_or_generate_keypair() -> x25519.X25519PrivateKey:
    """Load existing keypair or prompt to generate one."""
    if KEYPAIR_PATH.exists():
        return x25519.X25519PrivateKey.from_private_bytes(
            KEYPAIR_PATH.read_bytes()
        )
    print("[-] No asymmetric key pair found.")
    resp = input("    Generate one now? [Y/n]: ").strip().lower()
    if resp.startswith("n"):
        raise KeyNotFound("Cannot proceed without a key pair.")
    private = x25519.X25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    KEYPAIR_PATH.write_bytes(private_bytes)
    os.chmod(KEYPAIR_PATH, 0o600)
    pub = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print(f"[+] Key pair generated and saved to {KEYPAIR_PATH}")
    print(f"[+] Your public key (share this): {base64.b64encode(pub).decode()}")
    return private


def encrypt_asym(plaintext: str, peer_pubkey_b64: str) -> str:
    """
    Encrypt a message for a recipient using their X25519 public key.
    Provides forward secrecy via ephemeral key generation.
    """
    peer_raw = base64.b64decode(peer_pubkey_b64)
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_raw)

    # Ephemeral key pair — generated fresh for each message
    ephemeral_private = x25519.X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(peer_pub)

    # Derive a symmetric AES-256 key via HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cryptovault-asymmetric-v1",
    ).derive(shared_secret)

    _zero_bytes_via_buffer(shared_secret)

    # Encrypt using the derived symmetric key
    fake_kid = base64.b16encode(os.urandom(KEY_ID_BYTES)).decode().lower()
    fake_entry = KeyEntry(
        key_id=fake_kid, key_bytes=aes_key, created="now", active=True
    )
    inner_ct_b64 = encrypt(plaintext, fake_entry)

    # Pack: ephemeral public key (32 bytes) + inner ciphertext
    ephem_pub = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    packed = ephem_pub + base64.b64decode(inner_ct_b64)
    result = base64.b64encode(packed).decode()

    _zero_bytes_via_buffer(aes_key)
    return result


def decrypt_asym(ciphertext_b64: str, private_key: x25519.X25519PrivateKey) -> str:
    """
    Decrypt a message encrypted with your public key.
    Extracts the sender's ephemeral public key from the ciphertext,
    re-derives the shared AES key, and decrypts.
    """
    try:
        raw = base64.b64decode(ciphertext_b64)
    except Exception as ex:
        raise DecryptFailed(f"Invalid base64: {ex}")

    if len(raw) < 33:
        raise DecryptFailed(
            "Ciphertext too short to be a valid asymmetric payload "
            "(needs at least 32 bytes for ephemeral key + 1 byte ciphertext)."
        )

    ephem_pub_bytes = raw[:32]
    inner_payload   = raw[32:]

    ephem_pub = x25519.X25519PublicKey.from_public_bytes(ephem_pub_bytes)
    shared_secret = private_key.exchange(ephem_pub)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cryptovault-asymmetric-v1",
    ).derive(shared_secret)

    _zero_bytes_via_buffer(shared_secret)

    try:
        # Parse the inner symmetric ciphertext
        version, kid, nonce, ct_and_tag = _parse_full_payload(inner_payload)
        gcm = AESGCM(aes_key)
        plaintext = gcm.decrypt(nonce, ct_and_tag, b"")
        return plaintext.decode("utf-8")
    except InvalidTag:
        raise DecryptFailed(
            "Asymmetric decryption failed. Wrong private key or tampered data."
        )
    finally:
        _zero_bytes_via_buffer(aes_key)


# ════════════════════════════════════════════════════════════
#  ENCRYPTED VAULT (with HMAC Integrity Protection)
# ════════════════════════════════════════════════════════════
# Labels are stored in plaintext (so you can list what you have),
# but the actual message content is always encrypted. The entire
# file is HMAC-SHA256 signed to detect tampering.
#
# Ethical Note: Use encryption ethically and responsibly. Always
# keep your encryption keys safe. Losing the key means you cannot
# decrypt your data.

@dataclass
class _VaultEntry:
    label: str
    ciphertext: str
    key_id: str
    created: str
    aad: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "ct": self.ciphertext,
            "key_id": self.key_id,
            "created": self.created,
            "aad": self.aad,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "_VaultEntry":
        return cls(
            label=d["label"],
            ciphertext=d["ct"],
            key_id=d.get("key_id", ""),
            created=d.get("created", ""),
            aad=d.get("aad", ""),
        )


class Vault:
    """
    An encrypted message vault protected by HMAC integrity checking.
    
    Practical Use:
    - Secure storage of sensitive text data
    - Learning how cryptographic keys and encryption algorithms work
    - Protecting notes, passwords, and confidential documents
    - A foundational cybersecurity project to understand confidentiality principles
    """

    def __init__(self, path: Path = VAULT_PATH):
        self.path = path
        self._entries: Dict[str, _VaultEntry] = {}
        self._hmac_key: bytes = b""
        self._load()

    def _compute_hmac(self, data: bytes) -> str:
        """Compute HMAC-SHA256 over the serialized payload."""
        if not self._hmac_key:
            return ""
        return hmac.new(self._hmac_key, data, hashlib.sha256).hexdigest()

    def set_key(self, key: bytes) -> None:
        """Set the HMAC signing key. Called after keystore initialization."""
        self._hmac_key = key

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except json.JSONDecodeError:
            raise VaultTampered("Vault file is corrupted (invalid JSON).")

        stored_hmac = raw.get("hmac", "")
        payload = raw.get("payload", {})

        # Verify HMAC before trusting any data
        if stored_hmac and self._hmac_key:
            payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False)
            expected = self._compute_hmac(payload_json.encode("utf-8"))
            if not hmac.compare_digest(stored_hmac, expected):
                raise VaultTampered(
                    "VAULT HMAC MISMATCH! The vault file may have been tampered with.\n"
                    "Use encryption ethically and responsibly. Always keep your "
                    "encryption keys safe."
                )

        self._entries = {}
        for entry_data in payload.values():
            entry = _VaultEntry.from_dict(entry_data)
            self._entries[entry.label] = entry

    def _save(self) -> None:
        pdata = {label: e.to_dict() for label, e in self._entries.items()}
        data = {"version": FORMAT_VERSION, "payload": pdata}
        if self._hmac_key:
            pjson = json.dumps(pdata, sort_keys=True, ensure_ascii=False)
            data["hmac"] = self._compute_hmac(pjson.encode("utf-8"))
        self.path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        try:
            os.chmod(self.path, 0o600)
        except NotImplementedError:
            pass

    def store(self, label: str, plaintext: str, ks: KeyStore, aad: str = "") -> None:
        """
        Encrypt a message and store it under a label in the vault.
        Losing the key means you cannot decrypt your data — keep it safe!
        """
        key = ks.active()
        ct = encrypt(plaintext, key, aad)
        entry = _VaultEntry(
            label=label,
            ciphertext=ct,
            key_id=key.key_id,
            created=datetime.now(timezone.utc).isoformat(),
            aad=aad,
        )
        self._entries[label] = entry
        self._save()
        print(f"[+] Vault: Saved '{label}' (encrypted with key {key.key_id[:16]}...)")

    def retrieve(self, label: str, ks: KeyStore) -> Tuple[str, str]:
        """Decrypt a vault entry by label. Returns (plaintext, key_id_used)."""
        if label not in self._entries:
            raise KeyNotFound(f"No vault entry with label '{label}'.")
        entry = self._entries[label]
        return decrypt(entry.ciphertext, ks, aad=entry.aad)

    def list_entries(self) -> List[dict]:
        """List all vault entries with metadata. Plaintext is never exposed."""
        return [
            {"label": e.label, "key_id": e.key_id, "created": e.created}
            for e in self._entries.values()
        ]

    def delete(self, label: str) -> None:
        """Remove a vault entry permanently."""
        if label not in self._entries:
            raise KeyNotFound(f"No vault entry with label '{label}'.")
        del self._entries[label]
        self._save()
        print(f"[+] Vault: Deleted '{label}'.")


# ════════════════════════════════════════════════════════════
#  COMMAND-LINE INTERFACE
# ════════════════════════════════════════════════════════════

def print_banner() -> None:
    print("""
 ╔══════════════════════════════════════════════════════════════╗
 ║            Encryption / Decryption Tool                     ║
 ║     AES-256-GCM · X25519 · PBKDF2 · HMAC-SHA256 Vault      ║
 ║                                                             ║
 ║  Practical Use:                                             ║
 ║  • Secure storage of sensitive text data                    ║
 ║  • Learning how cryptographic keys and encryption work      ║
 ║  • Protecting notes, passwords, and confidential documents  ║
 ║  • A foundational cybersecurity project                     ║
 ║  • Secure communication between trusted parties             ║
 ║                                                             ║
 ║  Ethical Note: Use encryption ethically and responsibly.    ║
 ║  Always keep your encryption keys safe. Losing the key      ║
 ║  means you cannot decrypt your data.                        ║
 ╚══════════════════════════════════════════════════════════════╝
""")


def print_help() -> None:
    print_banner()
    print("""
USAGE:
  python cryptovault.py <command> [options]

── KEY MANAGEMENT ──────────────────────────────────────────
  --generate [note]               Generate a secure encryption key
  --list-keys                     List all saved keys
  --rotate [note]                 Rotate active key (generates new)
  --revoke <key_id>               Remove a key from keystore

── ENCRYPT / DECRYPT (Symmetric, Key-Based) ───────────────
  --encrypt <message>             Encrypt a message with active key
  --decrypt <ciphertext>          Decrypt a message
  --stdin                         Read input from stdin (pipe mode)
  --encrypt-file <path>           Encrypt a file
  --decrypt-file <path>           Decrypt a file

── PASSWORD MODE (No Key File Needed) ─────────────────────
  --encrypt-pw <message>          Encrypt with a password
  --decrypt-pw <ciphertext>       Decrypt with a password

── ASYMMETRIC ENCRYPTION (X25519) ─────────────────────────
  --keygen-asym                   Generate X25519 key pair
  --pubkey                        Show your public key
  --encrypt-asym <pubkey> <msg>   Encrypt for someone using their public key
  --decrypt-asym <ciphertext>     Decrypt with your private key

── VAULT ──────────────────────────────────────────────────
  --vault-store <label> <msg>     Store an encrypted message
  --vault-list                    List stored entries
  --vault-read <label>            Decrypt and read an entry
  --vault-del <label>             Delete a vault entry

── OTHER ──────────────────────────────────────────────────
  --interactive                   Interactive menu mode
  --aad <text>                    Additional authenticated data context
  --help                          Show this message

EXAMPLES:
  python cryptovault.py --generate
  python cryptovault.py --encrypt "Hello, this is secret!"
  python cryptovault.py --decrypt "gAAAAAB..."
  python cryptovault.py --encrypt-pw "My secret message"
  python cryptovault.py --encrypt-file document.pdf
  python cryptovault.py --stdin < secret.txt
  python cryptovault.py --interactive

ETHICAL NOTE:
  Use encryption ethically and responsibly. Always keep your encryption
  keys safe. Losing the key means you cannot decrypt your data.
""")


def interactive_mode() -> None:
    """Run the tool in interactive menu mode."""
    print_banner()
    ks = KeyStore()
    vault = Vault()
    try:
        vault.set_key(ks.active().key_bytes)
    except KeyNotFound:
        vault.set_key(b"")

    while True:
        print()
        print("─── Main Menu ───")
        print("  1)  Generate new encryption key")
        print("  2)  List keys")
        print("  3)  Rotate active key")
        print("  4)  Encrypt a message")
        print("  5)  Decrypt a message")
        print("  6)  Encrypt a file")
        print("  7)  Decrypt a file")
        print("  8)  Encrypt with password (no key file)")
        print("  9)  Decrypt with password")
        print(" 10)  Generate X25519 key pair")
        print(" 11)  Encrypt with public key (asymmetric)")
        print(" 12)  Decrypt with private key (asymmetric)")
        print(" 13)  Vault — store encrypted message")
        print(" 14)  Vault — list entries")
        print(" 15)  Vault — read decrypted message")
        print(" 16)  Vault — delete entry")
        print("  0)  Exit")
        choice = input("\nSelect an option: ").strip()

        try:
            if choice == "0":
                print(
                    "\nRemember: Always keep your encryption keys safe. "
                    "Losing the key means you cannot decrypt your data."
                )
                break

            elif choice == "1":
                note = input("  Note (optional): ").strip()
                e = ks.generate(note)
                vault.set_key(ks.active().key_bytes)
                print(f"  [OK] Generated key: {e.key_id}")

            elif choice == "2":
                keys = ks.list_all()
                if not keys:
                    print("  No keys found. Generate one with option 1.")
                else:
                    print(f"  {'ID':<20} {'Created':<30} {'Status':<10} {'Note'}")
                    print("  " + "-" * 80)
                    for k in keys:
                        status = "ACTIVE" if k["active"] else "inactive"
                        print(
                            f"  {k['id']:<20} {k['created']:<30} "
                            f"{status:<10} {k['note']}"
                        )

            elif choice == "3":
                note = input("  Note for new key (optional): ").strip()
                e = ks.rotate(note)
                vault.set_key(ks.active().key_bytes)
                print(f"  [OK] Active key rotated to: {e.key_id}")

            elif choice == "4":
                msg = input("  Message to encrypt: ")
                aad = input("  AAD context (optional): ").strip()
                print(f"\n  [Ciphertext]:\n  {encrypt(msg, ks.active(), aad)}")

            elif choice == "5":
                ct = input("  Ciphertext: ")
                aad = input("  AAD context (optional): ").strip()
                pt, kid = decrypt(ct, ks, aad)
                print(
                    f"\n  [Plaintext] (decrypted with key {kid[:16]}...):\n  {pt}"
                )

            elif choice == "6":
                path = input("  File path: ").strip()
                encrypt_file(Path(path), ks.active())

            elif choice == "7":
                path = input("  File path: ").strip()
                decrypt_file(Path(path), ks)

            elif choice == "8":
                msg = input("  Message to encrypt: ")
                pw = getpass.getpass("  Password: ")
                print(f"\n  [Password-Encrypted]:\n  {encrypt_with_password(msg, pw)}")

            elif choice == "9":
                ct = input("  Ciphertext: ")
                pw = getpass.getpass("  Password: ")
                pt = decrypt_with_password(ct, pw)
                print(f"\n  [Decrypted]:\n  {pt}")

            elif choice == "10":
                _load_or_generate_keypair()

            elif choice == "11":
                pk = input("  Recipient's public key (base64): ").strip()
                msg = input("  Message: ")
                print(f"\n  [Asymmetric Ciphertext]:\n  {encrypt_asym(msg, pk)}")

            elif choice == "12":
                ct = input("  Ciphertext: ").strip()
                priv = _load_or_generate_keypair()
                pt = decrypt_asym(ct, priv)
                print(f"\n  [Decrypted]:\n  {pt}")

            elif choice == "13":
                label = input("  Label: ").strip()
                msg = input("  Message: ")
                aad = input("  AAD context (optional): ").strip()
                vault.store(label, msg, ks, aad)

            elif choice == "14":
                entries = vault.list_entries()
                if not entries:
                    print("  Vault is empty.")
                else:
                    print(f"  {'Label':<30} {'Key ID':<20} {'Created'}")
                    print("  " + "-" * 70)
                    for e in entries:
                        print(
                            f"  {e['label']:<30} {e['key_id'][:16]:<20} "
                            f"{e['created']}"
                        )

            elif choice == "15":
                label = input("  Label: ").strip()
                pt, kid = vault.retrieve(label, ks)
                print(
                    f"\n  [{label}] (decrypted with {kid[:16]}...):\n  {pt}"
                )

            elif choice == "16":
                label = input("  Label: ").strip()
                vault.delete(label)

            else:
                print("  Invalid option. Try again.")

        except CryptoError as e:
            print(f"  [ERROR] {e}")
        except KeyboardInterrupt:
            print("\n  [Interrupted]")
        except Exception as e:
            print(f"  [ERROR] Unexpected: {e}")


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("--help", "-h"):
        print_help()
        sys.exit(0)

    args = sys.argv[1:]

    # Parse global flags
    aad = ""
    if "--aad" in args:
        i = args.index("--aad")
        if i + 1 < len(args):
            aad = args[i + 1]
            args.pop(i)
            args.pop(i)

    stdin_mode = "--stdin" in args
    if stdin_mode:
        args.remove("--stdin")

    # Initialize keystore and vault
    ks = KeyStore()
    vault = Vault()
    try:
        vault.set_key(ks.active().key_bytes)
    except KeyNotFound:
        vault.set_key(b"")

    cmd = args[0]

    try:
        # ── Key Management ─────────────────────────────────────
        if cmd == "--generate":
            note = " ".join(args[1:])
            e = ks.generate(note)
            vault.set_key(ks.active().key_bytes)

        elif cmd == "--list-keys":
            keys = ks.list_all()
            if not keys:
                print("No keys found. Generate one with --generate.")
            else:
                print(f"{'Key ID':<20} {'Created':<30} {'Status':<10} {'Note'}")
                print("-" * 80)
                for k in keys:
                    status = "ACTIVE" if k["active"] else "inactive"
                    print(
                        f"{k['id']:<20} {k['created']:<30} "
                        f"{status:<10} {k['note']}"
                    )

        elif cmd == "--rotate":
            note = " ".join(args[1:])
            e = ks.rotate(note)
            vault.set_key(ks.active().key_bytes)
            print(f"Active key: {e.key_id}")

        elif cmd == "--revoke":
            if len(args) < 2:
                print("Usage: --revoke <key_id>")
                sys.exit(1)
            ks.revoke(args[1])

        # ── Symmetric Encrypt/Decrypt ──────────────────────────
        elif cmd == "--encrypt":
            if stdin_mode:
                plaintext = sys.stdin.read()
            elif len(args) < 2:
                print("Usage: --encrypt <message>")
                sys.exit(1)
            else:
                plaintext = args[1]
            print(encrypt(plaintext, ks.active(), aad))

        elif cmd == "--decrypt":
            if len(args) < 2:
                print("Usage: --decrypt <ciphertext>")
                sys.exit(1)
            pt, kid = decrypt(args[1], ks, aad)
            print(pt)

        elif cmd == "--encrypt-file":
            if len(args) < 2:
                print("Usage: --encrypt-file <path>")
                sys.exit(1)
            encrypt_file(Path(args[1]), ks.active())

        elif cmd == "--decrypt-file":
            if len(args) < 2:
                print("Usage: --decrypt-file <path>")
                sys.exit(1)
            decrypt_file(Path(args[1]), ks)

        # ── Password Mode ──────────────────────────────────────
        elif cmd == "--encrypt-pw":
            if stdin_mode:
                plaintext = sys.stdin.read()
            elif len(args) < 2:
                print("Usage: --encrypt-pw <message>")
                sys.exit(1)
            else:
                plaintext = args[1]
            pw = getpass.getpass("Password: ")
            print(encrypt_with_password(plaintext, pw))

        elif cmd == "--decrypt-pw":
            if len(args) < 2:
                print("Usage: --decrypt-pw <ciphertext>")
                sys.exit(1)
            pw = getpass.getpass("Password: ")
            pt = decrypt_with_password(args[1], pw)
            print(pt)

        # ── Asymmetric ─────────────────────────────────────────
        elif cmd == "--keygen-asym":
            priv = _load_or_generate_keypair()
            pub = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            print(f"Your public key: {base64.b64encode(pub).decode()}")

        elif cmd == "--pubkey":
            if not KEYPAIR_PATH.exists():
                print("No key pair found. Run --keygen-asym first.")
                sys.exit(1)
            priv = x25519.X25519PrivateKey.from_private_bytes(
                KEYPAIR_PATH.read_bytes()
            )
            pub = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            print(base64.b64encode(pub).decode())

        elif cmd == "--encrypt-asym":
            if len(args) < 3:
                print("Usage: --encrypt-asym <pubkey_b64> <message>")
                sys.exit(1)
            print(encrypt_asym(args[2], args[1]))

        elif cmd == "--decrypt-asym":
            if len(args) < 2:
                print("Usage: --decrypt-asym <ciphertext>")
                sys.exit(1)
            if not KEYPAIR_PATH.exists():
                print("No key pair found. Run --keygen-asym first.")
                sys.exit(1)
            priv = x25519.X25519PrivateKey.from_private_bytes(
                KEYPAIR_PATH.read_bytes()
            )
            pt = decrypt_asym(args[1], priv)
            print(pt)

        # ── Vault ──────────────────────────────────────────────
        elif cmd == "--vault-store":
            if len(args) < 3:
                print("Usage: --vault-store <label> <message>")
                sys.exit(1)
            vault.store(args[1], args[2], ks, aad)

        elif cmd == "--vault-list":
            entries = vault.list_entries()
            if not entries:
                print("Vault is empty.")
            else:
                print(f"{'Label':<30} {'Key ID':<20} {'Created'}")
                print("-" * 70)
                for e in entries:
                    print(
                        f"{e['label']:<30} {e['key_id'][:16]:<20} {e['created']}"
                    )

        elif cmd == "--vault-read":
            if len(args) < 2:
                print("Usage: --vault-read <label>")
                sys.exit(1)
            pt, kid = vault.retrieve(args[1], ks)
            print(pt)

        elif cmd == "--vault-del":
            if len(args) < 2:
                print("Usage: --vault-del <label>")
                sys.exit(1)
            vault.delete(args[1])

        # ── Interactive ────────────────────────────────────────
        elif cmd == "--interactive":
            interactive_mode()

        else:
            print(f"Unknown command: {cmd}")
            print("Run with --help to see available commands.")
            sys.exit(1)

    except CryptoError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(
            "\nGoodbye. Remember: Always keep your encryption keys safe. "
            "Losing the key means you cannot decrypt your data."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()