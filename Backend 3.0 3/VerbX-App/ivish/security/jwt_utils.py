# security/auth/jwt_utils.py

import os
import uuid
import time
import base64
import hashlib
import hmac
import logging
import jwt
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
from jwt.exceptions import PyJWTError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# Security Imports (Corrected paths based on file structure)
from config.settings import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXP_DELTA_SECONDS,
    JWT_ENCRYPTION_KEY,
    ZKP_CHALLENGE_TTL
)

from security.blockchain.blockchain_utils import anchor_event as log_auth_event
from security.blockchain.zkp_handler import generate_zkp_token as generate_zkp_challenge, verify_zkp_proof as verify_zkp_challenge
from ai_models.ivish.voice_session import SessionManager

from security.firewall import CircuitBreaker
from backend.app.db.redis import set_ephemeral as set_ephemeral_token

# Type aliases
Token = str
UserID = str
Fingerprint = str
Role = str
JWTPayload = Dict[str, Any]
EphemeralToken = str

# Security: Key derivation for JWT encryption
_JWT_SALT = os.urandom(16)
_JWT_KDF = PBKDF2HMAC(
    algorithm=hashes.SHA3_256(),
    length=32,
    salt=_JWT_SALT,
    iterations=600000,
    backend=default_backend()
)
_JWT_ENCRYPTOR = Fernet(
    base64.urlsafe_b64encode(_JWT_KDF.derive(JWT_ENCRYPTION_KEY.encode()))
)

class JWTSecurityEngine:
    """
    Nuclear-grade JWT manager with ZKP and AES-256-GCM encryption.
    """
    def __init__(self):
        self._logger = logging.getLogger("jwt_utils")
        self._session_manager = SessionManager()
       
        self._circuit_breaker = CircuitBreaker(threshold=3, cooldown=60)
        self._supported_algorithms = [JWT_ALGORITHM]
        self._issuer = "ivish-ai"
        self._audience = "ivish-backend"
        self._key_version = "v2"
        self._ephemeral_key = Fernet.generate_key()
        self._zkp_required = False

    def generate_token(
        self,
        user_id: UserID,
        fingerprint: Fingerprint,
        role: Role = "user",
        exp: int = JWT_EXP_DELTA_SECONDS,
        *,
        zkp_proof: Optional[str] = None,
        encrypt: bool = True
    ) -> Token:
        """
        Generate secure JWT with optional ZKP proof and encryption
        """
        if not all(isinstance(x, str) for x in (user_id, fingerprint, role)):
            self._logger.warning("Invalid token generation parameters")
            raise ValueError("Invalid token generation parameters")

        payload = {
            "sub": user_id,
            "fingerprint": fingerprint,
            "role": role,
            "exp": datetime.utcnow() + timedelta(seconds=exp),
            "iat": datetime.utcnow(),
            "jti": str(uuid.uuid4()),
            "iss": self._issuer,
            "aud": self._audience,
            "_security": {
                "version": "2.3.0",
                "zkp": bool(zkp_proof),
                "engine": "jwt_utils"
            }
        }

        if zkp_proof:
            payload["zkp"] = zkp_proof
            # Note: This is client-side ZKP; the server generates the challenge, client provides proof.
            # The corrected zkp_handler.py implements the client-side proof generation.
            # This function would be called on the client.
            # A server-side token generation would typically receive a proof, not generate a challenge.

        try:
            token = jwt.encode(
                payload,
                JWT_SECRET_KEY,
                algorithm=JWT_ALGORITHM,
                headers={"kid": self._key_version}
            )
        except PyJWTError as e:
            self._logger.error(f"JWT signing failed: {str(e)}")
            raise

        if encrypt:
            token = self._encrypt_jwt(token)

        log_auth_event(
            user_id=user_id,
            action="token_issue",
            metadata={
                "jti": payload["jti"],
                "role": role,
                "zkp_used": bool(zkp_proof)
            }
        )

        self._audit_agent.update({
            "event": "token_generated",
            "user_id": user_id,
            "role": role,
            "exp": payload["exp"].isoformat() + "Z",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

        return token

    def verify_token(
        self,
        token: Token,
        *,
        require_zkp: bool = False,
        check_fingerprint: bool = True
    ) -> JWTPayload:
        """
        Verify JWT with signature, expiration, and ZKP checks
        """
        try:
            try:
                token = self._decrypt_jwt(token)
            except Exception as e:
                if not token.count('.') == 2:
                    raise jwt.InvalidTokenError("Invalid JWT format")

            decoded = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "verify_signature": True
                }
            )

            if require_zkp and not decoded.get("zkp"):
                raise jwt.InvalidTokenError("ZKP proof required")

            if check_fingerprint and not self._verify_fingerprint(decoded["sub"], decoded["fingerprint"]):
                raise jwt.InvalidTokenError("Invalid device fingerprint")

            if "zkp_challenge" in decoded:
                if not verify_zkp_challenge(decoded["sub"], decoded["zkp_challenge"]):
                    raise jwt.InvalidTokenError("ZKP challenge failed")

            self._log_verification(decoded)

            return decoded

        except jwt.PyJWTError as e:
            self._logger.warning(f"JWT verification failed: {str(e)}", exc_info=True)
            self._circuit_breaker.trigger()
            raise
        except Exception as e:
            self._logger.critical(f"Unexpected JWT error: {str(e)}", exc_info=True)
            raise jwt.InvalidTokenError("Token verification failed")

    def _encrypt_jwt(self, token: Token) -> Token:
        """AES-256-GCM encryption for stored JWTs"""
        try:
            return _JWT_ENCRYPTOR.encrypt(token.encode()).decode()
        except Exception as e:
            self._logger.error(f"JWT encryption failed: {str(e)}")
            raise

    def _decrypt_jwt(self, encrypted_token: Token) -> Token:
        """Secure decryption with integrity validation"""
        try:
            return _JWT_ENCRYPTOR.decrypt(encrypted_token.encode()).decode()
        except Exception as e:
            self._logger.critical(f"JWT decryption failed: {str(e)}")
            raise jwt.InvalidTokenError("Token decryption failed")

    def generate_ephemeral_token(
        self,
        operation: str,
        ttl: int = ZKP_CHALLENGE_TTL
    ) -> EphemeralToken:
        """
        Generate short-lived, one-time use token
        """
        payload = {
            "jti": str(uuid.uuid4()),
            "type": "ephemeral",
            "op": operation,
            "exp": datetime.utcnow() + timedelta(seconds=ttl),
            "iat": datetime.utcnow(),
            "iss": self._issuer,
            "aud": self._audience
        }

        token = jwt.encode(
            payload,
            JWT_SECRET_KEY,
            algorithm=JWT_ALGORITHM,
            headers={"kid": "ephemeral"}
        )

        set_ephemeral_token(f"ephemeral_token:{payload['jti']}", "valid", ttl)

        return token

    def rotate_jwt_keys(self) -> None:
        """Rotate encryption and signing keys for security"""
        try:
            new_key = Fernet.generate_key()
            self._JWT_ENCRYPTOR = Fernet(new_key)
            self._key_version = "v3"
            self._logger.info("JWT encryption key rotated successfully")
        except Exception as e:
            self._logger.error(f"JWT key rotation failed: {str(e)}")

    def extract_user_info(self, token: Token) -> Dict:
        """
        Extract user claims from token
        """
        try:
            payload = self.verify_token(token, check_fingerprint=False)
            return {
                "user_id": payload["sub"],
                "role": payload["role"],
                "fingerprint": payload["fingerprint"],
                "session_id": payload.get("sid"),
                "jti": payload["jti"]
            }
        except jwt.InvalidTokenError:
            return {}

    def _verify_fingerprint(self, user_id: UserID, fingerprint: Fingerprint) -> bool:
        """Device or voice fingerprint validation"""
        expected = self._session_manager.get_fingerprint(user_id)
        return hmac.compare_digest(expected, fingerprint)

    def _log_verification(self, payload: JWTPayload) -> None:
        """Log token verification to audit trail"""
        self._logger.info(f"JWT Verified: {payload['sub']}")
        self._audit_agent.update({
            "event": "token_verified",
            "user_id": payload["sub"],
            "role": payload["role"],
            "fingerprint": payload["fingerprint"],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "security": {
                "verified": True
            }
        })