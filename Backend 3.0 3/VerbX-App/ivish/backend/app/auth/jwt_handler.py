import hmac
import os
import time
import uuid
import jwt
import hashlib
import logging
import asyncio
import json
import base64
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Union, List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException, status

# Internal imports - CORRECTED PATHS
from ..security.blockchain.blockchain_utils import log_to_blockchain, secure_audit_log as blockchain_secure_audit_log
# from ..utils.logger import BaseLogger
# from backend.app.db.redis import RedisCache
# from security.intrusion_prevention.counter_response import BlackholeRouter, rotate_endpoint
# from security.firewall import Firewall as TokenFirewall
# from utils.security import encrypt_data, decrypt_data
# from middlewares.rate_limiter import RateLimiter

# --- Hardcoded constants (from non-existent config file) ---
# NOTE: In a production environment, these should be managed via a secrets manager.
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
TOKEN_EXPIRY_SECONDS = int(os.getenv("TOKEN_EXPIRY_SECONDS", 900))  # 15 minutes
TOKEN_REFRESH_EXPIRY_SECONDS = int(os.getenv("TOKEN_REFRESH_EXPIRY_SECONDS", 86400))  # 24 hours
TOKEN_REFRESH_WINDOW_SECONDS = int(os.getenv("TOKEN_REFRESH_WINDOW_SECONDS", 300))
TOKEN_RATE_LIMIT = int(os.getenv("TOKEN_RATE_LIMIT", 10))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", 60))
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", 5))

# Security constants
_IVISH_JWT_SECRET = os.getenv("IVISH_JWT_SECRET", os.urandom(32).hex()).encode()
_IVISH_JWT_REFRESH_SECRET = os.getenv("IVISH_JWT_REFRESH_SECRET", os.urandom(32).hex()).encode()
_IVISH_HW_FINGERPRINT = os.getenv("HW_FINGERPRINT", "default_fingerprint")

# Singleton with rate limit
# _rate_limiter = RateLimiter()
# _blackhole_router = BlackholeRouter()
# logger = BaseLogger("JWTHandler")

class JWTHandler:
    def __init__(self, redis_cache: Any):
        self._revocation_cache = redis_cache
        self._firewall = TokenFirewall()

    def _hash_device_fingerprint(self, device_id: str) -> str:
        """Securely hash a device fingerprint."""
        return hashlib.sha3_256(device_id.encode()).hexdigest()

    async def _is_revoked(self, jti: str) -> bool:
        """Check if a token's JTI is in the persistent revocation cache."""
        return bool(await self._revocation_cache.get(f"revoked:{jti}"))

    async def _add_to_revocation_list(self, jti: str) -> None:
        """Add a token's JTI to the persistent revocation cache."""
        # Set a generous expiry for the revoked token to ensure it remains invalid
        await self._revocation_cache.set(f"revoked:{jti}", "true", ex=TOKEN_REFRESH_EXPIRY_SECONDS + 3600)

    async def generate_token(
        self,
        user_id: str,
        device_fingerprint: str,
        roles: Optional[List[str]] = None,
        consent_flags: Optional[Dict[str, bool]] = None,
        zkp_validated: bool = False
    ) -> Dict[str, Any]:
        """
        Generates a new access token and a refresh token. ZKP is assumed to be
        validated prior to this call, and a claim is added to the payload.
        """
        try:
            if not await _rate_limiter.check_limit(user_id, rate=TOKEN_RATE_LIMIT, window=RATE_LIMIT_WINDOW):
                await _blackhole_router.trigger()
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

            issued_at = datetime.now(timezone.utc)
            expiry = issued_at + timedelta(seconds=TOKEN_EXPIRY_SECONDS)
            refresh_expiry = issued_at + timedelta(seconds=TOKEN_REFRESH_EXPIRY_SECONDS)

            payload = {
                "sub": user_id, "roles": roles or [], "consent": consent_flags or {},
                "iat": issued_at.timestamp(), "exp": expiry.timestamp(),
                "jti": str(uuid.uuid4()), "dfp": self._hash_device_fingerprint(device_fingerprint),
                "zkp_validated": zkp_validated
            }
            refresh_token_payload = payload.copy()
            refresh_token_payload["exp"] = refresh_expiry.timestamp()
            refresh_token_payload["refresh"] = True
            
            access_token = jwt.encode(payload, _IVISH_JWT_SECRET, algorithm=JWT_ALGORITHM)
            refresh_token = jwt.encode(refresh_token_payload, _IVISH_JWT_REFRESH_SECRET, algorithm=JWT_ALGORITHM)

            return {"status": "success", "token": access_token, "refresh_token": refresh_token}
        except HTTPException as e:
            raise e
        except Exception as e:
            await logger.log_event(f"Token generation failed: {str(e)}", level="CRITICAL")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token generation failed")

    async def verify_token(self, token: str, device_fingerprint: str) -> Dict[str, Any]:
        """
        Verifies the access token against a secret, expiration, and device fingerprint.
        Also checks the revocation list.
        """
        try:
            decoded = jwt.decode(token, _IVISH_JWT_SECRET, algorithms=[JWT_ALGORITHM])
            jti = decoded.get("jti")
            if not jti or await self._is_revoked(jti):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token is revoked or invalid")
            
            if not self._validate_device_binding(decoded, device_fingerprint):
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Device mismatch or fingerprint invalid")
            
            # The token simply carries the claim that ZKP was validated, it doesn't contain the proof.
            if decoded.get("zkp_validated") is not True:
                # Optionally, handle tokens without a ZKP claim differently
                pass

            return {"status": "valid", "payload": decoded}
        except jwt.ExpiredSignatureError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
        except jwt.InvalidTokenError as e:
            await logger.log_event(f"Invalid token error: {str(e)}", level="ALERT")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")

    def _validate_device_binding(self, decoded: Dict[str, Any], device_id: str) -> bool:
        """Ensures the token is only used on the device it was issued for."""
        current_dfp = self._hash_device_fingerprint(device_id)
        return hmac.compare_digest(decoded.get("dfp", ""), current_dfp)

    async def refresh_token(self, refresh_token: str, device_fingerprint: str) -> Dict[str, Any]:
        """Generates a new access token using a valid refresh token."""
        try:
            decoded = jwt.decode(refresh_token, _IVISH_JWT_REFRESH_SECRET, algorithms=[JWT_ALGORITHM])
            if not decoded.get("refresh"):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not a refresh token")

            jti = decoded.get("jti")
            if not jti or await self._is_revoked(jti):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token is revoked or invalid")

            if not self._validate_device_binding(decoded, device_fingerprint):
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Device mismatch")

            # Invalidate the old refresh token to prevent replay attacks
            await self._add_to_revocation_list(jti)
            
            new_tokens = await self.generate_token(
                user_id=decoded["sub"],
                device_fingerprint=device_fingerprint,
                roles=decoded.get("roles"),
                consent_flags=decoded.get("consent"),
                zkp_validated=decoded.get("zkp_validated", False)
            )
            
            return {"status": "success", "token": new_tokens["token"], "refresh_token": new_tokens["refresh_token"]}

        except jwt.ExpiredSignatureError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token has expired")
        except Exception as e:
            await logger.log_event(f"Refresh failed: {str(e)}", level="ALERT")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token failed")

    async def revoke_token(self, jti: str) -> Dict[str, Any]:
        """Revokes a token by adding its JTI to the revocation list."""
        try:
            if not jti:
                raise ValueError("JTI is required for token revocation.")
            await self._add_to_revocation_list(jti)
            await logger.log_event(f"Token with JTI {jti} revoked.", level="INFO")
            return {"status": "revoked", "jti": jti}
        except Exception as e:
            await logger.log_event(f"Token revocation failed: {str(e)}", level="ERROR")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Revocation failed: {e}")

    async def get_user_data_from_token(self, token: str, device_fingerprint: str) -> Dict[str, Any]:
        """
        Decodes and verifies a token and returns a comprehensive user data payload.
        This consolidates multiple redundant methods from the original code.
        """
        try:
            verified_payload = await self.verify_token(token, device_fingerprint)
            user_data = {
                "user_id": verified_payload["payload"]["sub"],
                "roles": verified_payload["payload"].get("roles", []),
                "consent": verified_payload["payload"].get("consent", {}),
                "issued_at": verified_payload["payload"].get("iat"),
                "expires_at": verified_payload["payload"].get("exp"),
                "jti": verified_payload["payload"].get("jti")
            }
            return user_data
        except HTTPException:
            raise
        except Exception as e:
            await logger.log_event(f"Failed to get user data from token: {str(e)}", level="ERROR")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def validate_session_token(token: str) -> bool:
    # Stub function for validating session token
    return True
