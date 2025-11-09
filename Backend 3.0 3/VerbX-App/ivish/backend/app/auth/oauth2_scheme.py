import os
import uuid
import time
import jwt
import hmac
import hashlib
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt as jose_jwt
from pydantic import BaseModel, Field, validator

# Internal imports - CORRECTED PATHS

from security.blockchain.blockchain_utils import verify_did_signature, log_to_blockchain
from security.blockchain.zkp_handler import verify_zkp_identity
from backend.app.utils.security import validate_session_binding, SessionManager, generate_ephemeral_token

# External imports - Corrected
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from security.intrusion_prevention.counter_response import BlackholeRouter

# Type aliases
Token = str
UserID = str
SessionID = str
Scope = str

# Security: Secure RNG and HMAC key
_SECURE_RNG = os.urandom
_JWT_HMAC_KEY = hashlib.sha256(b'VerbX_JWT_INTEGRITY_KEY').digest()
_JWT_SECRET = os.getenv("JWT_SECRET", "super_secret_key")
_JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_BLACKHOLE_ROUTER = BlackholeRouter()

class TokenPayload(BaseModel):
    sub: UserID
    scopes: List[Scope] = []
    sid: Optional[SessionID] = None
    did_sig: Optional[str] = None
    iat: int
    exp: int

class SecureOAuth2Scheme:
    def __init__(self):
        self._logger = logging.getLogger("oauth_scheme")
        self._session_manager = SessionManager()
        self._scheme = OAuth2PasswordBearer(
            tokenUrl="/auth/token",
            scheme_name="IvishOAuth2",
            scopes={
                "ai:read": "Read AI resources", "ai:write": "Modify AI resources", "memory:access": "Access user memory",
                "tts:stream": "Stream TTS", "stt:stream": "Stream STT", "autocoder:write": "Auto-generate code"
            }
        )

    def get_oauth_scheme(self):
        return self._scheme

    async def get_current_user(
        self,
        request: Request,
        token: str = Depends(self._scheme)
    ) -> Dict[str, Any]:
        if not self._verify_jwt_integrity(token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Token tampering detected")
        try:
            payload = jose_jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
            token_data = TokenPayload(**payload)
            client_fingerprint = request.headers.get("X-Client-Fingerprint")
            if not validate_session_binding(token_data.sid, client_fingerprint):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Session fingerprint mismatch")
            if not await verify_zkp_identity(token_data.sub):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="ZKP identity verification failed")
            if token_data.did_sig and not await verify_did_signature(token_data.sub, token_data.did_sig):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid DID signature")
            user_data = {"user_id": token_data.sub, "scopes": token_data.scopes, "session_id": token_data.sid}
            await log_to_blockchain("token_validated", payload={"user_id": token_data.sub, "scopes": token_data.scopes, "session_id": token_data.sid})
            return user_data
        except JWTError as e:
            self._logger.warning(f"JWT validation failed: {str(e)}"); raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})
        except Exception as e:
            self._logger.error(f"Permission check failed: {str(e)}", exc_info=True); raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Access validation failed")

    def _verify_jwt_integrity(self, token: str) -> bool:
        try:
            header, payload, signature = token.split('.')
            msg = f"{header}.{payload}".encode()
            computed_hmac = hmac.new(_JWT_HMAC_KEY, msg, 'sha256').hexdigest()
            return hmac.compare_digest(computed_hmac[:len(signature)], signature)
        except Exception as e:
            self._logger.error(f"JWT integrity check failed: {str(e)}"); return False

    async def validate_token(self, token: str) -> bool:
        try:
            return self._verify_jwt_integrity(token) and bool(jose_jwt.get_unverified_claims(token).get("sub"))
        except Exception as e:
            self._logger.error(f"Token validation failed: {str(e)}"); return False

    async def get_user_scopes(self, token: str) -> List[Scope]:
        if not self._verify_jwt_integrity(token): return []
        try: return TokenPayload(**jose_jwt.get_unverified_claims(token)).scopes
        except Exception as e: self._logger.error(f"Scope extraction failed: {str(e)}"); return []

# Singleton instance
oauth_scheme = SecureOAuth2Scheme()
oauth2_scheme = oauth_scheme.get_oauth_scheme()
get_current_user = oauth_scheme.get_current_user