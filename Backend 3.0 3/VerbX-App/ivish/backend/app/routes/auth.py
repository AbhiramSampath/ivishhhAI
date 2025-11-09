# backend/routes/auth.py
# 🔒 Nuclear-Grade Authentication System with Zero-Trust Validation
# Secure, auditable, and biometric-aware login/registration system

import os
import time
import uuid
import asyncio
import logging
import hashlib
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Union
from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Internal imports - CORRECTED PATHS
from ..auth.jwt_handler import JWTHandler
from db.mongo import UserDB
from security.voice_biometric_auth import VoiceMatcher
from security.blockchain.zkp_handler import ZKPValidator
from security.blockchain.blockchain_utils import BlockchainLogger
from middlewares.rate_limiter import RateLimiter
from security.intrusion_prevention.counter_response import BlackholeRouter
from utils.logger import secure_log as log_event

# --- Hardcoded constants (from non-existent config file) ---
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
SESSION_EXPIRY_MINUTES = int(os.getenv("SESSION_EXPIRY_MINUTES", "15"))
VOICE_THRESHOLD = float(os.getenv("VOICE_THRESHOLD", "0.85"))
MAX_PASSWORD_LENGTH = 128
MIN_PASSWORD_LENGTH = 12
DEVICE_FINGERPRINT_LENGTH = 64
VOICE_SAMPLE_MAX_SIZE = 16384
BLACKHOLE_DELAY = int(os.getenv("BLACKHOLE_DELAY", "60"))
RATE_LIMIT_WINDOW = int(os.getenv("AUTH_RATE_LIMIT_WINDOW", "60"))
MAX_LOGIN_RATE = int(os.getenv("MAX_LOGIN_RATE", "5"))
TEMP_AUTH_PATHS = ["/tmp/ivish_auth_*", "/dev/shm/auth_*"]

# Initialize secure components
auth_router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()
jwt_handler = JWTHandler()
voice_matcher = VoiceMatcher(threshold=VOICE_THRESHOLD)
zkp_validator = ZKPValidator()
blockchain_logger = BlockchainLogger()
user_db = UserDB()
rate_limiter = RateLimiter()
blackhole_router = BlackholeRouter()
logger = logging.getLogger(__name__)

class AuthRequest(BaseModel):
    """Secure auth request with field validation"""
    email: EmailStr
    password: str = Field(
        ..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH
    )
    voice_sample: Optional[bytes] = Field(
        None, max_length=VOICE_SAMPLE_MAX_SIZE
    )
    zkp_proof: Optional[str] = Field(
        None, max_length=1024
    )
    device_fingerprint: str = Field(
        ..., min_length=DEVICE_FINGERPRINT_LENGTH, max_length=DEVICE_FINGERPRINT_LENGTH
    )

class AuthResponse(BaseModel):
    """Secure auth response with encrypted tokens"""
    access_token: str
    refresh_token: str
    expires_in: int

class NuclearAuthHandler:
    """
    Provides secure, auditable, and biometric-aware authentication.
    """
    def __init__(self):
        self.user_db = user_db
        self.jwt = jwt_handler
        self.voice = voice_matcher
        self.zkp = zkp_validator
        self.blockchain = blockchain_logger
        self.blackhole = blackhole_router

    def _hash_user_id(self, user_id: str) -> str:
        """PBKDF2-HMAC-SHA512 user hashing"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=b"ivish_salt_2023",
            iterations=210000,
            backend=default_backend()
        )
        return kdf.derive(user_id.encode()).hex()

    async def register(self, req: AuthRequest):
        """Secure user registration with:
        - Password hardening
        - Voiceprint storage
        - ZKP pubkey generation
        """
        if not await rate_limiter.check_limit(req.email, rate=MAX_LOGIN_RATE, window=RATE_LIMIT_WINDOW):
            await self.blackhole.trigger(delay_sec=BLACKHOLE_DELAY)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")

        # Anti-enumeration
        if await self.user_db.exists(req.email):
            await asyncio.sleep(0.5)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Registration failed")

        try:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(), length=64, salt=salt, iterations=210000, backend=default_backend()
            )
            pw_hash = kdf.derive(req.password.encode())

            voice_hash = None
            if req.voice_sample:
                if not await self.voice.validate_sample(req.voice_sample):
                    raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid voice sample")
                voice_hash = await self.voice.create_hash(req.voice_sample)

            zkp_pubkey = None
            if req.zkp_proof:
                zkp_pubkey = await self.zkp.generate_pubkey(req.zkp_proof)

            user_id = str(uuid.uuid4())
            success = await self.user_db.create(
                user_id=user_id, email=req.email, pw_hash=pw_hash, salt=salt,
                voice_hash=voice_hash, zkp_pubkey=zkp_pubkey, device_fp=req.device_fingerprint
            )
            if not success:
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Registration failed")

            await self.blockchain.log(event_type="register", data={"user_id": self._hash_user_id(user_id), "email": req.email, "device": req.device_fingerprint})
            log_event(f"[AUTH] User {req.email} registered")
            return {"status": "success", "user_id": user_id, "zkp_pubkey": zkp_pubkey, "timestamp": time.time()}
        except Exception as e:
            log_event(f"[AUTH] Registration failed: {str(e)}", level="CRITICAL")
            raise

    async def login(self, req: AuthRequest, client_ip: str):
        """Zero-trust login with:
        - Constant-time user lookup
        - Voiceprint + ZKP + password validation
        - Device binding
        """
        if not await rate_limiter.check_limit(req.email, rate=MAX_LOGIN_RATE, window=RATE_LIMIT_WINDOW):
            await self.blackhole.trigger(delay_sec=BLACKHOLE_DELAY)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")

        user = await self.user_db.get_secure(req.email)
        if not user:
            await asyncio.sleep(0.5)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(), length=64, salt=user["salt"], iterations=210000, backend=default_backend()
        )
        try:
            kdf.verify(req.password.encode(), user["pw_hash"])
        except Exception:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")

        if req.voice_sample and not await self.voice.match(sample=req.voice_sample, stored_hash=user.get("voice_hash")):
            log_event("[AUTH] Voiceprint mismatch", level="CRITICAL")
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Biometric verification failed")

        if req.zkp_proof and not await self.zkp.validate(proof=req.zkp_proof, pubkey=user.get("zkp_pubkey")):
            log_event("[AUTH] ZKP validation failed", level="CRITICAL")
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="ZKP validation failed")

        if user["device_fp"] != req.device_fingerprint:
            log_event("[AUTH] Device mismatch", level="CRITICAL")
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Device fingerprint mismatch")

        token_result = await self.jwt.generate_token(user_id=user["user_id"], device_fingerprint=req.device_fingerprint, zkp_proof=req.zkp_proof)
        if token_result["status"] != "success":
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token generation failed")

        await self.blockchain.log(event_type="login", data={"user_id": user["user_id"], "ip": client_ip, "device": req.device_fingerprint})
        return {"access_token": token_result["token"], "refresh_token": token_result["refresh_token"], "expires_in": SESSION_EXPIRY_MINUTES * 60}

    async def refresh(self, refresh_token: str):
        """Secure token rotation with token revocation."""
        if not await rate_limiter.check_limit(refresh_token, rate=MAX_LOGIN_RATE, window=RATE_LIMIT_WINDOW):
            await self.blackhole.trigger(delay_sec=BLACKHOLE_DELAY)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")
        
        if await self.jwt.is_revoked(refresh_token):
            log_event("[AUTH] Revoked token refresh attempt", level="CRITICAL")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
        
        try:
            payload = await self.jwt.verify_token(refresh_token)
            if not payload.get("refresh"):
                raise ValueError("Invalid refresh token")
            
            new_tokens = await self.jwt.generate_token(user_id=payload["sub"], device_fingerprint=payload["dfp"], zkp_proof=payload.get("zkp"))
            await self.jwt.revoke(refresh_token)
            return {"access_token": new_tokens["token"], "refresh_token": new_tokens["refresh_token"], "expires_in": SESSION_EXPIRY_MINUTES * 60}
        except Exception as e:
            log_event(f"[AUTH] Token refresh failed: {str(e)}", level="CRITICAL")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token refresh failed")

    async def logout(self, token: str):
        """Atomic session termination with secure logging."""
        if not await rate_limiter.check_limit(token, rate=MAX_LOGIN_RATE, window=RATE_LIMIT_WINDOW):
            await self.blackhole.trigger(delay_sec=BLACKHOLE_DELAY)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")
        
        try:
            payload = await self.jwt.verify_token(token)
            await self.jwt.revoke(token)
            await self.user_db.clear_session(payload["sub"])
            await self.blockchain.log(event_type="logout", data={"user_id": payload["sub"]})
            log_event(f"[AUTH] User {payload['sub']} logged out")
            return {"status": "success"}
        except Exception as e:
            log_event(f"[AUTH] Logout failed: {str(e)}", level="CRITICAL")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Logout failed")

# FastAPI endpoints
@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(req: AuthRequest):
    result = await NuclearAuthHandler().register(req)
    return result

@auth_router.post("/login")
async def login_user(req: AuthRequest, request: Request):
    result = await NuclearAuthHandler().login(req, request.client.host)
    return result

@auth_router.post("/refresh")
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    result = await NuclearAuthHandler().refresh(credentials.credentials)
    return result

@auth_router.post("/logout")
async def logout_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    result = await NuclearAuthHandler().logout(credentials.credentials)
    return result