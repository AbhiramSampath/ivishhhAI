# backend/routes/feedback.py

import asyncio
import os
import time
import hashlib
import hmac
import logging
import json
import base64
from typing import Dict, List, Optional, Union, Any
from fastapi import APIRouter, HTTPException, Request, Depends, status, Header
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from collections import defaultdict
from motor.motor_asyncio import AsyncIOMotorClient

# Project Imports - CORRECTED PATHS
from db.connection import get_db
from security.blockchain.blockchain_utils import log_to_blockchain
from utils.logger import log_event
from ..auth.jwt_handler import verify_user_token, verify_admin_token
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.ivish.memory_agent import MemorySessionHandler
from security.intrusion_prevention.counter_response import BlackholeRouter
from security.blockchain.zkp_handler import ZeroKnowledgeProof
from ai_models.self_learning.autocoder import AutoCoder
from middlewares.rate_limiter import RateLimiter
from ..services.report_service import report_incident
from ai_models.autocoder.codegen_engine import generate_test_case as autocoder_generate_test

# Initialize secure components
logger = logging.getLogger(__name__)
memory_handler = MemorySessionHandler()
autocoder = AutoCoder()
blackhole_router = BlackholeRouter()
rate_limiter = RateLimiter()

# Feedback Constants
_FEEDBACK_ENCRYPTION_KEY = os.getenv("FEEDBACK_ENCRYPTION_KEY", Fernet.generate_key().decode())
_FEEDBACK_HMAC_KEY = os.getenv("FEEDBACK_HMAC_KEY", "default_hmac_key").encode()
_MIN_RATING_TRIGGER = int(os.getenv("MIN_RATING_TRIGGER", 2))
_TTL_DAYS = int(os.getenv("FEEDBACK_TTL_DAYS", 30))
_FEEDBACK_TYPES = {"suggestion", "bug", "abuse", "compliment"}
_DEFAULT_KDF_ITERATIONS = int(os.getenv("KDF_ITERATIONS", 600000))
_FEEDBACK_HASH_KEY = b"feedback_hash_key"

# Initialize router
router = APIRouter()

# Feedback Models
class FeedbackInput(BaseModel):
    """Secure feedback input model with validation"""
    user_id: str = Field(..., min_length=8, max_length=64)
    session_id: str = Field(..., min_length=12, max_length=128)
    feedback_text: str = Field(..., min_length=1, max_length=2000)
    rating: int = Field(..., ge=1, le=5)
    feedback_type: str = Field(..., regex="^(suggestion|bug|abuse|compliment)$")
    token: str
    voice_hash: Optional[str] = None
    zkp_proof: Optional[str] = None

class FeedbackResponse(BaseModel):
    """Secure feedback response model"""
    status: str
    message: str
    feedback_id: Optional[str] = None
    timestamp: str

class FeedbackStorage:
    """
    Secure feedback storage with:
    - Per-user encryption
    - HMAC integrity
    - Blockchain logging
    """
    def __init__(self):
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=os.getenv("FEEDBACK_KDF_SALT", "default_salt").encode(),
            iterations=_DEFAULT_KDF_ITERATIONS,
            backend=default_backend()
        )
        self._fernet_cache = {}
        self.fernet_key = _FEEDBACK_ENCRYPTION_KEY.encode()

    def _derive_key(self, user_id: str) -> bytes:
        if user_id in self._fernet_cache:
            return self._fernet_cache[user_id]
        
        key = base64.urlsafe_b64encode(self.kdf.derive(user_id.encode()))
        self._fernet_cache[user_id] = key
        return key

    async def encrypt_feedback(self, user_id: str, text: str) -> str:
        try:
            cipher = Fernet(self._derive_key(user_id))
            encrypted = cipher.encrypt(text.encode())
            return encrypted.decode()
        except Exception as e:
            log_event(f"FEEDBACK: Encryption failed - {str(e)}", level="ERROR")
            raise

    async def decrypt_feedback(self, user_id: str, encrypted: str) -> str:
        try:
            cipher = Fernet(self._derive_key(user_id))
            return cipher.decrypt(encrypted.encode()).decode()
        except Exception as e:
            log_event(f"FEEDBACK: Decryption failed - {str(e)}", level="WARNING")
            raise

    def sign_feedback(self, feedback: Dict) -> bytes:
        data = json.dumps(feedback, sort_keys=True).encode()
        return hmac.new(_FEEDBACK_HMAC_KEY, data, hashlib.sha256).digest()

    def verify_feedback(self, feedback: Dict, signature: bytes) -> bool:
        expected = self.sign_feedback(feedback)
        return hmac.compare_digest(signature, expected)

storage = FeedbackStorage()

class FeedbackRouter:
    def __init__(self):
        self._router = APIRouter()
        self._router.add_api_route("/submit-feedback", self.submit_feedback, methods=["POST"])
        self._router.add_api_route("/feedback/decrypt", self.decrypt_feedback_admin, methods=["GET"])

    @property
    def router(self):
        return self._router

    async def submit_feedback(
        self,
        data: FeedbackInput,
        request: Request,
        db: AsyncIOMotorClient = Depends(get_db)
    ) -> Dict[str, Any]:
        if not await rate_limiter.check_limit(data.user_id, rate=5, window=60):
            await blackhole_router.trigger()
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")
        
        if not await verify_user_token(data.token, data.user_id):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
        
        if data.zkp_proof and not await ZeroKnowledgeProof().verify(data.zkp_proof, data.user_id):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid ZKP proof")

        try:
            emotion = await detect_emotion(data.feedback_text[:500])
        except Exception as e:
            log_event(f"FEEDBACK: Emotion detection failed - {str(e)}", level="WARNING")
            emotion = "neutral"

        try:
            encrypted = await storage.encrypt_feedback(data.user_id, data.feedback_text)
        except Exception as e:
            log_event(f"FEEDBACK: Encryption failed - {str(e)}", level="ERROR")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Feedback encryption failed")

        feedback_doc = {
            "user_id": hashlib.sha256(data.user_id.encode()).hexdigest(),
            "session_id": data.session_id,
            "feedback": encrypted,
            "rating": data.rating,
            "type": data.feedback_type,
            "emotion": emotion,
            "timestamp": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=_TTL_DAYS),
            "ip": request.client.host,
            "user_agent": request.headers.get("user-agent", ""),
            "voice_hash": data.voice_hash,
            "signature": storage.sign_feedback(data.dict())
        }

        try:
            result = await db["feedback"].insert_one(feedback_doc)
            feedback_id = str(result.inserted_id)
            await log_to_blockchain("submit", data.user_id, feedback_id)
        except Exception as e:
            log_event(f"FEEDBACK: Storage failed - {str(e)}", level="ERROR")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Feedback processing error")

        if data.rating <= _MIN_RATING_TRIGGER or data.feedback_type in ["abuse", "bug"]:
            asyncio.create_task(self._trigger_critical_response(
                data.user_id, data.session_id, data.feedback_text, data.feedback_type, feedback_id
            ))

        return {
            "status": "success", "message": "Feedback recorded", "feedback_id": feedback_id,
            "timestamp": datetime.utcnow().isoformat()
        }

    async def decrypt_feedback_admin(
        self,
        user_id: str,
        encrypted: str,
        token: str = Header(...)
    ) -> Dict[str, Any]:
        if not await verify_admin_token(token):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid admin token")
        
        try:
            decrypted = await storage.decrypt_feedback(user_id, encrypted)
            return {"decrypted": decrypted}
        except Exception as e:
            log_event(f"FEEDBACK: Decryption failed - {str(e)}", level="ERROR")
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Decryption failed")

    async def _trigger_critical_response(
        self,
        user_id: str, session_id: str, feedback: str, issue_type: str, feedback_id: str
    ) -> None:
        try:
            await report_incident(user_id, session_id, feedback[:500], issue_type)
            if issue_type == "bug":
                test_case = await autocoder_generate_test(feedback)
                log_event(f"AUTOCODER: Generated test case for {session_id}", secure=True)
            asyncio.create_task(autocoder.optimize_feedback_pipeline(feedback_id))
        except Exception as e:
            log_event(f"CRITICAL FEEDBACK: Handler failed - {str(e)}", level="ERROR")

    async def _log_feedback_event(self, action: str, user_id: str, feedback_id: Optional[str] = None) -> None:
        asyncio.create_task(log_to_blockchain("feedback", {
            "user_id": user_id, "feedback_id": feedback_id, "action": action,
            "timestamp": datetime.utcnow().isoformat()
        }))

feedback_router = FeedbackRouter()
router = feedback_router.router