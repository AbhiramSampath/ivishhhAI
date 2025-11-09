#!/usr/bin/env python3
"""
🔐 Blockchain Identity Management Routes
Secure DID generation, private key export, and blockchain operations
"""

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import logging
from datetime import datetime

# Security imports
from backend.app.middlewares.rate_limiter import RateLimiter
from backend.app.security.jwt_handler import JWTHandler
from backend.app.security.security import SecurityManager
from security.blockchain.blockchain_utils import blockchain_utils
from security.blockchain.zkp_handler import ZKPHandler
from security.device_fingerprint import DeviceFingerprint
from security.encryption_utils import encrypt_for_transmission, decrypt_data

# Initialize components
rate_limiter = RateLimiter()
jwt_handler = JWTHandler()
security_manager = SecurityManager()
zkp_handler = ZKPHandler()
device_fingerprint = DeviceFingerprint()

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/blockchain",
    tags=["blockchain"],
    responses={404: {"description": "Not found"}},
)

class RegenerateDIDRequest(BaseModel):
    """
    📌 Request to regenerate user DID
    """
    user_id: str = Field(..., min_length=8, max_length=64, regex=r'^[a-zA-Z0-9_-]+$')
    device_fingerprint: str
    zkp_proof: str
    session_token: Optional[str] = None

class ExportPrivateKeyRequest(BaseModel):
    """
    📌 Request to export private key securely
    """
    user_id: str = Field(..., min_length=8, max_length=64, regex=r'^[a-zA-Z0-9_-]+$')
    device_fingerprint: str
    zkp_proof: str
    encryption_password: str = Field(..., min_length=8, max_length=128)
    session_token: Optional[str] = None

@router.post("/regenerate-did", status_code=status.HTTP_200_OK)
async def regenerate_did(request_payload: RegenerateDIDRequest):
    """
    🔐 Regenerate user DID with blockchain anchoring
    """
    try:
        # Rate limiting
        await rate_limiter.check_rate_limit(request_payload.user_id, "blockchain_regenerate_did")

        # ZKP verification
        if not zkp_handler.verify_proof(request_payload.zkp_proof, request_payload.user_id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "ZKP verification failed")

        # Device fingerprint validation
        if not device_fingerprint.validate(request_payload.device_fingerprint, request_payload.user_id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Device fingerprint validation failed")

        # JWT validation if session token provided
        if request_payload.session_token:
            jwt_handler.validate_token(request_payload.session_token)

        # Generate new DID
        did_result = await blockchain_utils.generate_did(
            user_id=request_payload.user_id,
            session_token=request_payload.session_token or "",
            zk_proof=request_payload.zkp_proof
        )

        if did_result["status"] != "success":
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"DID generation failed: {did_result.get('error', 'Unknown error')}")

        # Log blockchain event
        await blockchain_utils.anchor_event({
            "type": "DID_REGENERATION",
            "user_id": request_payload.user_id,
            "old_did": "previous_did_placeholder",  # In real implementation, get from DB
            "new_did": did_result["did"],
            "timestamp": datetime.now().isoformat()
        }, user_token=request_payload.session_token or "", zk_proof=request_payload.zkp_proof)

        response = {
            "success": True,
            "did": did_result["did"],
            "tx_hash": did_result.get("tx_hash"),
            "timestamp": datetime.now().isoformat()
        }
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"DID regeneration error: {str(e)}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "DID regeneration failed")

@router.post("/export-private-key", status_code=status.HTTP_200_OK)
async def export_private_key(request_payload: ExportPrivateKeyRequest):
    """
    🔐 Securely export user private key with encryption
    """
    try:
        # Rate limiting
        await rate_limiter.check_rate_limit(request_payload.user_id, "blockchain_export_key")

        # ZKP verification
        if not zkp_handler.verify_proof(request_payload.zkp_proof, request_payload.user_id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "ZKP verification failed")

        # Device fingerprint validation
        if not device_fingerprint.validate(request_payload.device_fingerprint, request_payload.user_id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Device fingerprint validation failed")

        # JWT validation if session token provided
        if request_payload.session_token:
            jwt_handler.validate_token(request_payload.session_token)

        # In real implementation, retrieve private key from secure storage
        # For now, generate a new key pair for demonstration
        did_result = await blockchain_utils.generate_did(
            user_id=request_payload.user_id,
            session_token=request_payload.session_token or "",
            zk_proof=request_payload.zkp_proof
        )

        if did_result["status"] != "success":
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Key export preparation failed")

        # Encrypt private key for transmission
        encrypted_key = encrypt_for_transmission(
            did_result["private_key"],
            request_payload.encryption_password
        )

        # Log blockchain event
        await blockchain_utils.anchor_event({
            "type": "PRIVATE_KEY_EXPORT",
            "user_id": request_payload.user_id,
            "did": did_result["did"],
            "timestamp": datetime.now().isoformat()
        }, user_token=request_payload.session_token or "", zk_proof=request_payload.zkp_proof)

        response = {
            "success": True,
            "encrypted_private_key": encrypted_key,
            "did": did_result["did"],
            "export_timestamp": datetime.now().isoformat(),
            "warning": "Store this encrypted key securely. Decryption requires the password provided."
        }
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Private key export error: {str(e)}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Private key export failed")
