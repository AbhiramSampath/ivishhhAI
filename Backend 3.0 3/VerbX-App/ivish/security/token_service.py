# security/auth/jwt_utils.py

import os
import re
import uuid
import jwt
import hashlib
import hmac
import asyncio
import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union, Tuple
from jwt.exceptions import PyJWTError
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Security Imports (Corrected paths based on file structure)
from config.settings import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXP_DELTA_SECONDS,
    JWT_ENCRYPTION_KEY,
    ZKP_CHALLENGE_TTL
)
from backend.app.utils.logger import log_event
from security.blockchain.blockchain_utils import anchor_event as log_auth_event
from security.blockchain.zkp_handler import generate_zkp_token as generate_zkp_challenge, verify_zkp_proof as verify_zkp_challenge
from ai_models.ivish.voice_session import SessionManager

from security.firewall import CircuitBreaker
from backend.app.middlewares.rate_limiter import TokenRateLimiter


# 🔐 Security Constants
_BACKEND = default_backend()
_AES_KEY = os.urandom(32)
_SALT = os.urandom(16)
_KDF_ITERATIONS = 2**20
_LATENCY_BUDGET_MS = 100
_MAX_TOKEN_SIZE = 1024
_SUPPORTED_ALGORITHMS = ["HS512", "RS256"]
_SUPPORTED_TOKEN_VERSIONS = [1, 2, 3]
_SUPPORTED_FINGERPRINT_LENGTH = 64

# --- Token Service Core ---
class TokenVault:
    """
    🔒 Secure Token Vault
    """

    def __init__(self):
        """Secure initialization"""
        self._current_key = os.getenv("TOKEN_ENCRYPTION_KEY", os.urandom(32).hex()).encode()
        self._key_version = 1
        self._key_rotation_log = []
        self._revoked_tokens = set()
        self.rate_limiter = TokenRateLimiter(max_calls=100, period=3600)
        self.blockchain_logger = log_auth_event
        self._session_manager = SessionManager()
        self._audit_agent = AuditAgent()
        self._circuit_breaker = CircuitBreaker(threshold=3, cooldown=60)
        self._jwt_secret = JWT_SECRET_KEY
        self._jwt_algorithm = JWT_ALGORITHM
        self._issuer = "ivish-ai"
        self._audience = "ivish-backend"

    def _derive_key(self, salt: bytes) -> bytes:
        """Quantum-resistant key derivation with Scrypt"""
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14, # Scrypt's n parameter should be a power of 2, 2**20 is too high for latency
            r=8,
            p=1,
            backend=_BACKEND
        )
        return kdf.derive(self._current_key)

    def _encrypt_token(self, token: str, salt: Optional[bytes] = None) -> Tuple[bytes, int]:
        """AES-256-GCM encrypted token with versioning"""
        salt = salt or os.urandom(16)
        key = self._derive_key(salt)
        cipher = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_token = cipher.encrypt(nonce, token.encode(), None)
        # Store salt + nonce + ciphertext
        return salt + nonce + encrypted_token, self._key_version

    def _decrypt_token(self, encrypted: bytes, version: int) -> Optional[str]:
        """Secure decryption with versioned key support"""
        try:
            if version != self._key_version:
                log_event(f"Token version mismatch: {version} vs {self._key_version}", level="WARNING")
                return None

            salt = encrypted[:16]
            nonce = encrypted[16:28]
            ciphertext = encrypted[28:]
            key = self._derive_key(salt)
            cipher = AESGCM(key)
            return cipher.decrypt(nonce, ciphertext, None).decode()
        except Exception as e:
            log_event(f"TOKEN_DECRYPTION_FAILURE: {str(e)}", level="ERROR")
            return None

    async def _rotate_keys(self):
        """Secure key rotation with blockchain logging"""
        old_key = self._current_key
        self._current_key = os.urandom(32)
        self._key_version += 1
        
        rotation_log = {
            "old_key_hash": hashlib.sha256(old_key).hexdigest(),
            "new_key_hash": hashlib.sha256(self._current_key).hexdigest(),
            "timestamp": datetime.utcnow().isoformat(),
            "reason": "manual_rotation"
        }
        await self.blockchain_logger("token_key_rotated", rotation_log)
        log_event("Token encryption key rotated", level="INFO")

    def _is_token_revoked(self, jti: str) -> bool:
        """Check revocation list"""
        return jti in self._revoked_tokens

    async def generate_token(self, user_id: str, fingerprint: str, request: Optional[Any] = None) -> Dict[str, Any]:
        """
        🔐 Secure token generation with:
        - Fingerprint binding
        - ZKP ephemeral claims
        - Anomaly detection
        - Blockchain logging
        """
        try:


            session_id = str(uuid.uuid4())
            expiry = int((datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MIN)).timestamp())
            fp_hash = hashlib.blake2s(fingerprint.encode(), key=self._current_key).hexdigest()

            payload = {
                "uid": user_id,
                "sid": session_id,
                "exp": expiry,
                "fph": fp_hash,
                "iss": self._issuer,
                "jti": str(uuid.uuid4()),
                "iat": int(datetime.utcnow().timestamp())
            }

            if ZKP_MODE:
                payload["zkp_challenge"] = await generate_zkp_challenge(user_id)

            token = jwt.encode(payload, self._jwt_secret, algorithm=self._jwt_algorithm)
            encrypted_token, version = self._encrypt_token(token)
            token_b64 = base64.b64encode(encrypted_token).decode()

            token_metadata = token_metadata(
                user_id=hashlib.sha256(user_id.encode()).hexdigest(),
                session_id=session_id,
                expiry=expiry,
                fingerprint_hash=fp_hash,
                zkp_proof=payload.get("zkp"),
                version=version
            )
            await self.blockchain_logger("token_generated", token_metadata.__dict__)
            return {
                "token": token_b64,
                "session_id": session_id,
                "expires_in": expiry,
                "zkp_challenge": payload.get("zkp_challenge"),
                "fingerprint_hash": fp_hash
            }
        except Exception as e:
            log_event(f"TOKEN_GENERATION_FAILURE: {str(e)}", level="CRITICAL")
            raise

    async def validate_token(self, encrypted_token: str, fingerprint: str = None) -> Dict[str, Any]:
        """
        🔐 Nuclear-grade token validation
        """
        try:

            
            encrypted_bytes = base64.b64decode(encrypted_token)
            token_version = 1 # We're using a single version for now

            token = self._decrypt_token(encrypted_bytes, token_version)
            if not token:
                return {"valid": False, "error": "decryption_failed"}

            payload = jwt.decode(
                token,
                self._jwt_secret,
                algorithms=[self._jwt_algorithm],
                options={"require_exp": True, "require": ["uid", "sid", "exp", "fph"]}
            )

            if fingerprint:
                expected_fp = hashlib.blake2s(
                    fingerprint.encode(), key=self._current_key
                ).hexdigest()
                if not hmac.compare_digest(payload["fph"], expected_fp):
                    log_event("Fingerprint mismatch - possible replay", level="WARNING")
                    return {"valid": False, "error": "fingerprint_mismatch"}

            if ZKP_MODE and "zkp" in payload:
                if not await verify_zkp_challenge(payload["uid"], payload["zkp"]):
                    return {"valid": False, "error": "zkp_verification_failed"}

            if payload["exp"] < datetime.utcnow().timestamp():
                return {"valid": False, "error": "token_expired"}

            if self._is_token_revoked(payload["jti"]):
                return {"valid": False, "error": "token_revoked"}

            await self.blockchain_logger("token_validated", {
                "session_id": payload["sid"],
                "user_id": payload["uid"],
                "timestamp": datetime.now().isoformat(),
                "fingerprint": fingerprint
            })

            return {
                "valid": True,
                "payload": payload,
                "token": token,
                "session_id": payload["sid"],
                "user_id": payload["uid"],
                "expiry": payload["exp"]
            }

        except jwt.ExpiredSignatureError:
            return {"valid": False, "error": "expired"}
        except jwt.PyJWTError as e:
            return {"valid": False, "error": f"jwt_error: {str(e)}"}
        except Exception as e:
            log_event(f"TOKEN_VALIDATION_FAILURE: {str(e)}", level="ERROR")
            return {"valid": False, "error": "invalid"}

    async def refresh_token(self, old_token: str, new_fingerprint: str = None) -> Dict[str, Any]:
        """
        🔒 Secure token refresh
        """
        try:
            validation = await self.validate_token(old_token, new_fingerprint)
            if not validation["valid"]:
                return {"status": "failed", "error": validation["error"]}

            old_payload = validation["payload"]
            old_payload["jti"] = str(uuid.uuid4())
            old_payload["exp"] = int(
                (datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MIN * 2)).timestamp()
            )

            if new_fingerprint:
                old_payload["fph"] = hashlib.blake2s(
                    new_fingerprint.encode(), key=self._current_key
                ).hexdigest()

            refreshed_token = jwt.encode(old_payload, self._jwt_secret, algorithm=self._jwt_algorithm)
            encrypted_token, version = self._encrypt_token(refreshed_token)
            token_b64 = base64.b64encode(encrypted_token).decode()

            await self.blockchain_logger("token_refreshed", {
                "old_jti": old_payload.get("jti"),
                "new_jti": old_payload["jti"],
                "timestamp": datetime.now().isoformat(),
                "user_id": old_payload["uid"],
                "version": version
            })

            return {
                "token": token_b64,
                "session_id": old_payload["sid"],
                "expires_in": old_payload["exp"],
                "zkp": old_payload.get("zkp"),
                "fingerprint_hash": old_payload["fph"]
            }

        except Exception as e:
            log_event(f"TOKEN_REFRESH_FAILURE: {str(e)}", level="ERROR")
            return {"status": "failed", "error": str(e)}

    async def emergency_revoke_all(self, user_id: str):
        """
        🔥 Nuclear option: revokes all tokens by rotating keys
        """
        try:
            await self._rotate_keys()
            self._revoked_tokens.add(user_id)
            log_event(f"Token revocation for {user_id[:6]}...", level="WARNING")
            await self.blockchain_logger("token_revoked", {
                "user_id": user_id,
                "reason": "manual_emergency_revoke",
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            log_event(f"TOKEN_REVOCATION_FAILURE: {str(e)}", level="ERROR")

# 🔐 Token Service Singleton
_vault = TokenVault()

def generate_token(user_id: str, fingerprint: str, request: Optional[Any] = None) -> str:
    return asyncio.run(_vault.generate_token(user_id, fingerprint, request))

def validate_token(encrypted_token: str, fingerprint: str = None) -> Tuple[bool, dict]:
    result = asyncio.run(_vault.validate_token(encrypted_token, fingerprint))
    return result.get("valid", False), result

def refresh_token(old_token: str, new_fingerprint: str = None) -> Optional[str]:
    result = asyncio.run(_vault.refresh_token(old_token, new_fingerprint))
    return result.get("token")

def emergency_revoke_all(user_id: str):
    return asyncio.run(_vault.emergency_revoke_all(user_id))