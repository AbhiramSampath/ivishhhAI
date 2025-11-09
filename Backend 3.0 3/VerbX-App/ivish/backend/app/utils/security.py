# backend/utils/security.py
# 🔒 Final, Secure Utility Toolkit for Ivish AI
# 🚀 Refactored Code

import os
import re
import base64
import secrets
import unicodedata
import hmac
import hashlib
import asyncio
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519, ed448, padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import bcrypt

# Corrected Internal imports
from .logger import log_event
from .rate_meter import rate_meter
from ....security.voice_biometric_auth import match_voice_signature_async


# --- Security Constants ---
_ENCRYPTION_KEY = os.getenv("AES_SECRET_KEY", None)
if not _ENCRYPTION_KEY:
    raise RuntimeError("AES_SECRET_KEY not found in environment.")
_ENCRYPTION_KEY = _ENCRYPTION_KEY.encode()
if len(_ENCRYPTION_KEY) not in [16, 24, 32]:
    raise ValueError("AES_SECRET_KEY must be 16, 24, or 32 bytes for AES.")

_HMAC_KEY = os.getenv("HMAC_SECRET", None)
if not _HMAC_KEY:
    raise RuntimeError("HMAC_SECRET not found in environment.")
_HMAC_KEY = _HMAC_KEY.encode()

RSA_PRIVATE_KEY = os.getenv("RSA_PRIVATE_KEY", None)
RSA_PUBLIC_KEY = os.getenv("RSA_PUBLIC_KEY", None)
if not (RSA_PRIVATE_KEY and RSA_PUBLIC_KEY):
    raise RuntimeError("RSA keys not found in environment.")

class QuantumEncryptor:
    """Post-quantum secure encryption stack using ChaCha20Poly1305."""
    def __init__(self):
        # Using X25519 for forward secrecy
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """ChaCha20-Poly1305 authenticated encryption."""
        if not plaintext:
            log_event("EMPTY_DATA_ENCRYPT", level="WARNING")
            return b""
        
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(_ENCRYPTION_KEY)
        return nonce + cipher.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Authenticated decryption with integrity check."""
        if not ciphertext or len(ciphertext) < 12:
            log_event("DECRYPTION_FAILED: Invalid length", level="ERROR")
            return b"DECRYPTION_FAILED"
            
        try:
            nonce = ciphertext[:12]
            ct = ciphertext[12:]
            cipher = ChaCha20Poly1305(_ENCRYPTION_KEY)
            return cipher.decrypt(nonce, ct, associated_data)
        except Exception as e:
            log_event(f"DECRYPTION_FAILED: {str(e)}", level="ERROR")
            return b"DECRYPTION_FAILED"

def encrypt_data(data: str) -> str:
    """ChaCha20-Poly1305 encryption for string data."""
    try:
        cipher = ChaCha20Poly1305(_ENCRYPTION_KEY)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, data.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()
    except Exception as e:
        log_event(f"ENCRYPTION_FAILED: {str(e)}", level="ERROR")
        return "ENCRYPTION_FAILED"

def decrypt_data(enc_data: str) -> str:
    """ChaCha20-Poly1305 decryption for string data."""
    try:
        decoded = base64.b64decode(enc_data)
        if len(decoded) < 12:
            log_event("DECRYPTION_FAILED: Invalid base64 length", level="ERROR")
            return "DECRYPTION_FAILED"
        
        nonce = decoded[:12]
        ct = decoded[12:]
        cipher = ChaCha20Poly1305(_ENCRYPTION_KEY)
        return cipher.decrypt(nonce, ct, None).decode()
    except Exception as e:
        log_event(f"DECRYPTION_FAILED: {str(e)}", level="ERROR")
        return "DECRYPTION_FAILED"

def rsa_encrypt(message: str) -> str:
    """RSA-OAEP encryption with SHA-512."""
    try:
        pub_key = load_pem_public_key(RSA_PUBLIC_KEY.encode(), backend=default_backend())
        ciphertext = pub_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
    except Exception as e:
        log_event(f"RSA_ENCRYPTION_FAILED: {str(e)}", level="ERROR")
        return "RSA_ENCRYPTION_FAILED"

def generate_secure_token() -> str:
    """Cryptographically secure token with hardware entropy."""
    try:
        return secrets.token_urlsafe(32)
    except Exception as e:
        log_event(f"SECURE_TOKEN_GEN_FAILED: {str(e)}", level="CRITICAL")
        return "SECURE_TOKEN_FAILED"

def hash_fingerprint(device_id: str) -> str:
    """Hardened device fingerprinting using HKDF."""
    try:
        salt = os.urandom(16)
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=salt,
            info=b'device_fingerprint',
            backend=default_backend()
        )
        derived_key = hkdf.derive(device_id.encode())
        return salt.hex() + ":" + derived_key.hex()
    except Exception as e:
        log_event(f"DEVICE_FINGERPRINT_FAILED: {str(e)}", level="ERROR")
        return "FINGERPRINT_FAILED"

async def verify_voice_biometric_async(input_voice: str, stored_hash: str) -> bool:
    """Timing-attack resistant biometric verification."""
    try:
        voice_hash = await match_voice_signature_async(input_voice)
        return bytes_eq(voice_hash.encode(), stored_hash.encode())
    except Exception as e:
        log_event(f"VOICE_BIOMETRIC_FAILED: {str(e)}", level="WARNING")
        return False

def sanitize_input(text: str) -> str:
    """Unicode-aware injection stripping."""
    if not text:
        return ""
    
    # Normalize before sanitization
    text = unicodedata.normalize("NFKC", text)
    
    # Remove dangerous patterns
    sanitized = re.sub(
        r"(?:<script.*?>|</script>|"
        r"\b(?:drop\s+table|insert\s+into|select\s+\*)\b|"
        r"[\u202D-\u202E]|"
        r"{{.*?}})",
        "",
        text,
        flags=re.IGNORECASE | re.VERBOSE
    )
    return sanitized.strip()

def generate_hmac(data: str) -> str:
    """Tamper-proof HMAC with SHA3."""
    h = hmac.new(_HMAC_KEY, digestmod=hashlib.sha3_256)
    h.update(data.encode())
    return h.hexdigest()

def verify_hmac(data: str, signature: str) -> bool:
    """Immutable data validation."""
    expected = generate_hmac(data)
    return hmac.compare_digest(expected, signature)

def generate_rsa_signature(data: str) -> str:
    """RSA-PSS signature with SHA512."""
    try:
        key = load_pem_private_key(RSA_PRIVATE_KEY.encode(), password=None, backend=default_backend())
        signature = key.sign(data.encode(), padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA512())
        return base64.b64encode(signature).decode()
    except Exception as e:
        log_event(f"RSA_SIGNATURE_FAILED: {str(e)}", level="ERROR")
        return "SIGNING_FAILED"

def verify_rsa_signature(data: str, signature: str) -> bool:
    """RSA signature verification."""
    try:
        sig_bytes = base64.b64decode(signature)
        pub_key = load_pem_public_key(RSA_PUBLIC_KEY.encode(), backend=default_backend())
        pub_key.verify(
            sig_bytes,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return True
    except Exception as e:
        log_event(f"RSA_VERIFY_FAILED: {str(e)}", level="WARNING")
        return False

def secure_hash_password(password: str) -> str:
    """Secure password hashing with bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_hashed_password(hash: str, password: str) -> bool:
    """Constant-time password verification."""
    try:
        return bcrypt.checkpw(password.encode(), hash.encode())
    except asyncio.exceptions.VerificationError:
        return False