import os
import uuid
import time
import jwt
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from functools import lru_cache

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp
from jose import JWTError
import asyncio

# Security imports - CORRECTED PATHS
from security.zkp_handler import verify_ephemeral_token
from security.blockchain.blockchain_utils import log_to_blockchain
from backend.services.permission_service import PermissionEngine
from ivish_central.user_safety_center import check_user_consent
from utils.logger import log_event
from security.jwt_handler import verify_jwt, extract_scopes

# Utils and config
ROUTE_PERMISSION_MAP = {
    "/chat": ["ai:read"],
    "/translate": ["ai:read", "ai:write"],
    "/memory": ["ai:read", "ai:private"],
    "/admin": ["ai:admin"]
}
CONSENT_REQUIRED = os.getenv("CONSENT_REQUIRED", "True").lower() == "true"
_HMAC_KEY = hashlib.sha256(b'VerbX_PERMISSION_HMAC_KEY').digest()
_SECURE_RNG = os.urandom
_JWT_ALGORITHM = "HS256"

class PermissionViolation(Exception):
    pass

class PermissionCheckerMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self._logger = logging.getLogger("permission_checker")
        self._permission_engine = PermissionEngine()

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method
        ip = request.client.host if request.client else "0.0.0.0"
        user_id = "UNKNOWN"
        scopes = []

        try:
            token = self._extract_token(request)
            payload = self._validate_jwt(token)
            user_id = payload["sub"]
            session_id = payload.get("sid", "none")
            scopes = payload.get("scopes", ["ai:read"])

            client_fingerprint = request.headers.get("X-Client-Fingerprint")
            if not self._validate_fingerprint(client_fingerprint, session_id):
                raise PermissionViolation("Fingerprint mismatch")

            if not self._check_route_permissions(scopes, path):
                raise PermissionViolation("Insufficient scopes")

            if CONSENT_REQUIRED and not await check_user_consent(user_id, path):
                raise PermissionViolation("Consent not granted")

            if "zk-token" in request.headers:
                if not await verify_ephemeral_token(request.headers["zk-token"], user_id):
                    raise PermissionViolation("ZK token invalid")

            await self._log_access(user_id, path, method, scopes, ip, "GRANTED")

            return await call_next(request)

        except PermissionViolation as e:
            await self._log_access(user_id, path, method, scopes, ip, f"DENIED: {str(e)}")
            return JSONResponse({"error": str(e)}, status_code=403, headers={"X-Permission-Failure": "1"})

        except JWTError:
            await self._log_access("UNKNOWN", path, method, [], ip, "DENIED: Invalid token")
            return JSONResponse({"error": "Invalid token"}, status_code=403, headers={"X-Permission-Failure": "1"})

        except Exception as e:
            await self._log_access("UNKNOWN", path, method, [], ip, f"ERROR: {str(e)}")
            self._logger.error(f"Permission check failed: {str(e)}", exc_info=True)
            raise HTTPException(status_code=401, detail="Access validation failed")

    def _extract_token(self, request: Request) -> str:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise PermissionViolation("Invalid auth scheme")
        return auth[7:]

    def _validate_jwt(self, token: str) -> Dict:
        try:
            payload = verify_jwt(token)
            if not payload:
                raise JWTError("Invalid token")
            return payload
        except JWTError:
            raise PermissionViolation("Invalid token")

    def _validate_fingerprint(self, client_fingerprint: Optional[str], session_id: str) -> bool:
        if not client_fingerprint:
            return False
        expected = hashlib.sha256(session_id.encode()).hexdigest()
        return hmac.compare_digest(expected.encode(), client_fingerprint.encode())

    def _check_route_permissions(self, user_scopes: Scopes, path: str) -> bool:
        required_scopes = ROUTE_PERMISSION_MAP.get(path, [])
        if not required_scopes:
            return True
        return all(scope in user_scopes for scope in required_scopes)

    def _check_consent(self, user_id: UserID, action: str) -> bool:
        if not CONSENT_REQUIRED:
            return True
        return self._permission_engine.check_consent(user_id, action)

    async def _verify_zk_token(self, token: str, user_id: UserID) -> bool:
        try:
            return await verify_ephemeral_token(token, user_id)
        except Exception as e:
            self._logger.warning(f"ZK token verification failed: {str(e)}")
            return False

    async def _log_access(self, **kwargs):
        log_data = {"timestamp": datetime.utcnow().isoformat() + "Z", **kwargs, "nonce": _SECURE_RNG(8).hex()}
        self._logger.info(f"PERMISSION AUDIT: {log_data}")
        try:
            await log_to_blockchain("permission_audit", log_data)
        except Exception as e:
            self._logger.warning(f"Blockchain logging failed: {str(e)}")

permission_checker_middleware = PermissionCheckerMiddleware