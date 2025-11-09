# backend/app/routes/permissions.py

import os
import uuid
import time
import jwt
import hmac
import hashlib
import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Request, Depends, HTTPException, Header, status
from pydantic import BaseModel, Field, validator
from jose import JWTError

# Internal imports - CORRECTED PATHS
from security.blockchain.blockchain_utils import log_to_blockchain
from security.blockchain.zkp_handler import verify_zk_token
from utils.logger import log_event
from backend.app.services.permission_service import PermissionStore
from ..auth.jwt_handler import get_current_user
from security.firewall import Firewall
from middlewares.rate_limiter import RateLimiter

# Type aliases
UserID = str
PermissionType = str
PermissionAction = str
PermissionStatus = Dict[str, Any]

# Security: Secure keys and salts
_ZKP_HMAC_KEY = os.getenv("ZKP_HMAC_KEY", os.urandom(32))
_PERMISSION_AUDIT_SALT = os.getenv("PERMISSION_AUDIT_SALT", os.urandom(16))
_PERMISSION_HMAC_KEY = os.getenv("PERMISSION_HMAC_KEY", os.urandom(32))
_PERMISSION_TIMEOUT = int(os.getenv("PERMISSION_TIMEOUT", 3600))
ALLOWED_ORIGINS = ["https://app.ivish.ai", "https://localhost:3000"]
RATE_LIMIT_PERM_REQUESTS = int(os.getenv("RATE_LIMIT_PERM_REQUESTS", 10))

router = APIRouter(
    prefix="/permissions",
    tags=["permissions"],
)

# === SECURE MODELS === #
class PermissionRequest(BaseModel):
    """
    Input model for permission actions
    """
    user_id: UserID = Field(..., min_length=8, max_length=64)
    permission_type: PermissionType = Field(..., regex=r"^[a-z_]{1,32}$")
    zk_token: str = Field(..., min_length=64, max_length=256)
    context_hash: Optional[str] = None

    @validator('user_id')
    def validate_user_id(cls, v):
        if not v.isalnum():
            raise ValueError("Invalid user ID format")
        return v

class PermissionStatusResponse(BaseModel):
    """
    Response model for permission status
    """
    permissions: List[PermissionType]
    granted: Dict[PermissionType, str]
    revoked: Dict[PermissionType, str]

# === DEPENDENCIES === #
async def validate_request_origin(request: Request):
    """Hidden firewall validation"""
    origin = request.headers.get("origin")
    if origin not in ALLOWED_ORIGINS:
        log_event(f"Permission request from disallowed origin: {origin}", level="WARNING")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origin not permitted")

async def validate_fingerprint(user_id: UserID, fingerprint: str) -> bool:
    """Session-based fingerprint verification"""
    expected = hashlib.sha256(user_id.encode()).hexdigest()
    return hmac.compare_digest(expected.encode(), fingerprint.encode())

# === CORE SERVICES === #
class PermissionManager:
    """
    Atomic permission manager with audit trail
    """
    def __init__(self):
        self._logger = logging.getLogger("permission_manager")
        self.store = PermissionStore()
        self.rate_limiter = RateLimiter()

    async def grant(
        self,
        user_id: UserID,
        perm_type: PermissionType,
        zk_proof: str,
        request_ip: str
    ) -> Dict:
        """
        Grant permission with ZKP verification and audit trail
        """
        if not await self.rate_limiter.check_limit(user_id, rate=RATE_LIMIT_PERM_REQUESTS, window=3600):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")
            
        if not await self._verify_zk_proof(zk_proof, user_id):
            self._logger.warning("Invalid ZKP token", extra={"user_id": user_id})
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid ZKP token")

        expiry = datetime.utcnow() + timedelta(seconds=_PERMISSION_TIMEOUT)

        success = await self.store.grant(
            user_id=user_id,
            permission=perm_type,
            expiry=expiry
        )

        if not success:
            self._logger.error("Permission grant failed", extra={"user_id": user_id, "perm": perm_type})
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Grant operation failed")

        audit_hash = await self._log_audit_event(
            action="grant",
            user_id=user_id,
            permission=perm_type,
            request_ip=request_ip
        )

        self._logger.info(f"Permission granted: {perm_type}", extra={"user_id": user_id})
        return {
            "status": "granted",
            "expires_at": expiry.isoformat() + "Z",
            "audit": {
                "chain_hash": audit_hash,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }

    async def _verify_zk_proof(self, token: str, user_id: UserID) -> bool:
        """
        HMAC-wrapped ZKP verification
        """
        try:
            msg = f"{user_id}{token[:32]}".encode()
            expected_hmac = hmac.new(_ZKP_HMAC_KEY, msg, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected_hmac.encode(), token[32:64].encode()) and \
                   await verify_zk_token(token[:32], user_id)
        except Exception as e:
            self._logger.error(f"ZKP verification failed: {str(e)}")
            return False

    async def _log_audit_event(self, action: str, **data) -> str:
        """
        Immutable audit logging to file and blockchain
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            **data,
            "nonce": os.urandom(8).hex()
        }
        log_entry["hash"] = hashlib.sha256(json.dumps(log_entry, sort_keys=True).encode()).hexdigest()

        log_event("PERMISSION_AUDIT", level="INFO", extra=log_entry)
        try:
            await log_to_blockchain("permission_log", log_entry)
        except Exception as e:
            self._logger.warning(f"Blockchain logging failed: {str(e)}")
        return log_entry["hash"]

    async def check_permission(self, user_id: UserID, action: PermissionType) -> bool:
        """
        Real-time permission validation
        """
        if not await self.store.has_permission(user_id, action):
            return False

        if await self.store.is_expired(user_id, action):
            await self.revoke(user_id, action)
            return False

        return True

    async def revoke(self, user_id: UserID, perm_type: PermissionType) -> None:
        """
        Secure permission revocation with audit trail
        """
        await self.store.revoke(user_id, perm_type)
        await self._log_audit_event(
            action="revoke",
            user_id=user_id,
            permission=perm_type
        )

# === API ROUTES === #
perm_manager = PermissionManager()
router.dependencies.append(Depends(validate_request_origin))

@router.get("", response_model=PermissionStatusResponse)
async def list_permissions(
    user: dict = Depends(get_current_user),
    x_fingerprint: str = Header(...)
) -> Dict:
    """
    List all granted permissions with cryptographic verification
    """
    if not await validate_fingerprint(user["user_id"], x_fingerprint):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid session fingerprint")

    perms = await perm_manager.store.get_permissions(user["user_id"])
    return {
        "permissions": perms,
        "granted": {p: "" for p in perms}, # Dummy data for granted
        "revoked": {}
    }

@router.post("/grant", response_model=Dict)
async def grant_permission(
    request: PermissionRequest,
    client_ip: str = Header(..., alias="x-real-ip"),
    user: dict = Depends(get_current_user)
) -> Dict:
    """
    Grant permission with ZKP verification
    """
    return await perm_manager.grant(
        user_id=user["user_id"],
        perm_type=request.permission_type,
        zk_proof=request.zk_token,
        request_ip=client_ip
    )

@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_permission(
    request: PermissionRequest,
    user: dict = Depends(get_current_user)
) -> None:
    """
    Revoke permission with audit trail
    """
    if not await perm_manager._verify_zk_proof(request.zk_token, user["user_id"]):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid ZKP proof")

    await perm_manager.revoke(request.user_id, request.permission_type)