# backend/app/routes/auth.py
# 🔒 Final, Secure Authentication Service
# 🚀 Refactored Code

import os
import re
import uuid
import hmac
import hashlib
import asyncio
import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache

# Corrected Security Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC as CryptoHMAC
from cryptography.hazmat.backends import default_backend

# Corrected Project Imports
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field, validator
from ....security.voice_biometric_auth import verify_voiceprint_async, detect_voice_spoofing_async
from ....security.blockchain.zkp_handler import ZKPAuthenticator
from ....security.blockchain.blockchain_utils import log_to_blockchain
from ..utils.rate_meter import rate_meter
from ....security.token_service import generate_token, verify_token, refresh_token_rotation
from ....security.token_service import QuantumSigner
from ..utils.logger import log_event
from ..models.user import get_user_by_id_async, verify_device_fingerprint_async
from ....security.intrusion_prevention.counter_response import blackhole_response_action

# 🔐 Security Constants
_BACKEND = default_backend()

# Load secrets and configuration from environment
_HMAC_KEY = os.getenv("AUTH_HMAC_KEY", None)
if not _HMAC_KEY:
    raise RuntimeError("AUTH_HMAC_KEY not found in environment.")
_HMAC_KEY = _HMAC_KEY.encode()

AUTH_EXPIRY_SECONDS = int(os.getenv("AUTH_EXPIRY_SECONDS", "900"))
REFRESH_SECRET = os.getenv("REFRESH_SECRET", None)
if not REFRESH_SECRET:
    raise RuntimeError("REFRESH_SECRET not found in environment.")

VOICE_THRESHOLD = float(os.getenv("VOICE_THRESHOLD", "0.85"))
_MAX_REFRESH_AGE_DAYS = int(os.getenv("MAX_REFRESH_AGE_DAYS", "7"))
_MIN_USER_ID_LENGTH = 8
_MAX_USER_ID_LENGTH = 64
_DEVICE_FINGERPRINT_REGEX = r'^[a-f0-9]{32,128}$'

logger = logging.getLogger(__name__)

@dataclass
class AuthResponse:
    access_token: str
    refresh_token: str
    expires_in: int
    qr_signature: str
    session_id: str
    timestamp: str
    _signature: Optional[str] = None

class AuthRequest(BaseModel):
    user_id: str = Field(..., min_length=_MIN_USER_ID_LENGTH, max_length=_MAX_USER_ID_LENGTH)
    voice_sample: bytes
    device_fingerprint: str
    zkp_proof: Dict[str, Any]
    session_nonce: str = Field(..., min_length=16, max_length=64)

    @validator("user_id")
    def validate_user_id(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]{8,64}$', v):
            raise ValueError("Invalid user ID format")
        return v

    @validator("device_fingerprint")
    def validate_device(cls, v):
        if not re.match(_DEVICE_FINGERPRINT_REGEX, v):
            raise ValueError("Invalid device fingerprint format")
        return v

class SecureAuthService:
    def __init__(self):
        self.zkp_authenticator = ZKPAuthenticator()
        self.quantum_signer = QuantumSigner()
        self.session_id = str(uuid.uuid4())
    
    def _sign_response(self, response_data: Dict) -> str:
        """HMAC-sign authentication response for integrity."""
        h = CryptoHMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        # Use a canonical representation to ensure consistent hashing
        canonical_data = json.dumps(response_data, sort_keys=True).encode()
        h.update(canonical_data)
        return h.finalize().hex()

    async def authenticate_user(self, request: AuthRequest) -> Dict:
        try:
            # 🔐 ZKP Identity Proof with ZKPAuthenticator
            if not await self.zkp_authenticator.verify_proof_async(
                request.user_id, request.zkp_proof, request.session_nonce
            ):
                await self._handle_malicious_attempt(request)
                raise HTTPException(403, "Identity verification failed")

            # 🚨 Rate Limiting & Brute-Force Protection
            if await rate_meter.track_call(request.user_id, source="auth_login"):
                await self._handle_brute_force_attempt(request)
                raise HTTPException(429, "Too many login attempts")

            # 🧠 Voiceprint Verification & Anti-Spoofing
            user = await get_user_by_id_async(request.user_id)
            if not user:
                await self._handle_malicious_attempt(request)
                raise HTTPException(404, "User not found")

            voice_match, is_spoof, device_ok = await asyncio.gather(
                verify_voiceprint_async(user["voiceprint_hash"], request.voice_sample),
                detect_voice_spoofing_async(request.voice_sample),
                verify_device_fingerprint_async(request.user_id, request.device_fingerprint)
            )

            if not (voice_match and not is_spoof and device_ok):
                await self._handle_failed_auth(request, {
                    "voice_match": voice_match,
                    "is_spoof": is_spoof,
                    "device_ok": device_ok
                })
                raise HTTPException(403, "Authentication failed")

            # ✅ Generate Secure Tokens
            access_token = generate_token(request.user_id, AUTH_EXPIRY_SECONDS)
            refresh_token = generate_token(request.user_id, _MAX_REFRESH_AGE_DAYS * 86400, secret=REFRESH_SECRET)
            qr_signature = self.quantum_signer.generate_signature(access_token)

            # 📜 Immutable Audit Trail
            await log_to_blockchain("auth_success", {
                "user_id": request.user_id,
                "device": request.device_fingerprint,
                "voice_hash": self._generate_sample_hash(request.voice_sample),
                "session_id": self.session_id,
                "timestamp": datetime.utcnow().isoformat()
            })

            response_data = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": AUTH_EXPIRY_SECONDS,
                "qr_signature": qr_signature,
                "session_id": self.session_id,
                "timestamp": datetime.utcnow().isoformat(),
            }
            response_data["_signature"] = self._sign_response(response_data)
            return response_data

        except Exception as e:
            await self._handle_auth_failure(request, str(e))
            raise HTTPException(500, "Authentication failed")

    async def _handle_failed_auth(self, request: AuthRequest, failure_reasons: dict):
        """Active defense for failed attempts."""
        await rate_meter.track_call(request.user_id, source="auth_fail")
        await log_to_blockchain("auth_failure", {
            "user_id": request.user_id,
            "reasons": failure_reasons,
            "device": request.device_fingerprint,
            "session_id": self.session_id,
            "timestamp": datetime.utcnow().isoformat()
        })
        await asyncio.sleep(3)

    async def _handle_auth_failure(self, request: AuthRequest, error: str):
        """Secure failure handling with audit trail."""
        await log_to_blockchain("auth_error", {
            "user_id": request.user_id,
            "error": error,
            "device": request.device_fingerprint,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def _handle_malicious_attempt(self, request: AuthRequest):
        """Counter-intelligence for ZKP failure."""
        await rate_meter.track_call(request.user_id, source="auth_malicious")
        log_event(f"ZKP_AUTH_FAILURE from {request.user_id}", level="ALERT")
        blackhole_response_action(delay=5)
        
    async def _handle_brute_force_attempt(self, request: AuthRequest):
        """Countermeasures for banned users."""
        log_event(f"Brute force attempt detected from {request.user_id}", level="ALERT")
        blackhole_response_action(delay=10)

    def _generate_sample_hash(self, voice_sample: bytes) -> str:
        """Voice sample fingerprinting using SHA-256."""
        digest = hashlib.sha256()
        digest.update(voice_sample)
        return digest.hexdigest()

    async def validate_token(self, token: str) -> Dict:
        try:
            payload = verify_token(token)
            if not payload:
                raise ValueError("Invalid token")
            
            # ⚛️ Validate quantum signature
            if not self.quantum_signer.validate_signature(token, payload.get("qr_signature")):
                raise ValueError("Quantum signature invalid")

            # 🔐 ZKP token validation
            if not await self.zkp_authenticator.verify_token_async(payload):
                raise ValueError("ZKP token validation failed")

            return payload

        except Exception as e:
            log_event(f"TOKEN_VALIDATION_FAILURE: {str(e)}", level="ERROR")
            return {"valid": False, "error": str(e)}

    async def rotate_refresh_token(self, old_token: str) -> Dict:
        return await refresh_token_rotation(old_token)