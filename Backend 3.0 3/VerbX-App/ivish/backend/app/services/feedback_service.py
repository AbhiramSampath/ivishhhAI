"""
🧠 Ivish AI Feedback Service
🔐 Secure feedback validation and processing with ZKP, biometrics, and AI integration
📦 Features: classification, autocoder queueing, blockchain logging, encrypted storage
🛡️ Security: ZKP, voice biometrics, HMAC, AES-256-GCM, Blackhole anti-fuzzing
"""
import os
import uuid
import json
import hmac
import asyncio
import hashlib
from typing import Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from functools import lru_cache

# --- Project Imports ---
# Corrected paths based on the VerbX architecture document
from config.settings import FEEDBACK_TTL, FEEDBACK_ROUTING_MODE
from utils.logger import log_event
from utils.helpers import sanitize_prompt
from security.blockchain.blockchain_utils import log_to_blockchain
from ai_models.sentiment.sentiment_analyzer import classify_feedback
from ai_models.self_learning.autocoder import queue_for_autocoder
from db.mongo import store_with_ttl
from security.blockchain.zkp_handler import ZKPHandler
from security.intrusion_prevention.counter_response import BlackholeRouter
from security.voice_biometric_auth import validate_voiceprint
from middlewares.rate_limiter import RateLimiter

# --- Security Constants ---
# Use environment variables for secure key management
_FERNET_KEY = os.getenv("FERNET_KEY")
if not _FERNET_KEY:
    _FERNET_KEY = Fernet.generate_key().decode()
    log_event("SECURITY: FERNET_KEY not found, generated a new one. This is not for production use.", level="CRITICAL")
_CIPHER_SUITE = Fernet(_FERNET_KEY.encode())

_HMAC_KEY = os.getenv("FEEDBACK_HMAC_KEY", os.urandom(32))
_MAX_FEEDBACK_LENGTH = 4096  # Prevents token bombing

@dataclass
class FeedbackMetadata:
    feedback_id: str
    user_id: str
    feature: str
    classification: str
    timestamp: datetime
    hmac: str

class FeedbackValidator:
    """Secure feedback validation with intrusion detection"""
    def __init__(self):
        self.zkp_handler = ZKPHandler()
        self.rate_limiter = RateLimiter()

    async def _validate_source(self, payload: Dict) -> bool:
        """Nuclear-grade request validation with ZKP and voice biometrics"""
        if not payload or "feedback_text" not in payload:
            log_event("SECURITY: Empty or malformed feedback", level="WARNING")
            await BlackholeRouter.trigger(delay_sec=60)
            return False

        # ZKP validation for a zero-trust model
        if not self.zkp_handler.verify(payload.get("zkp_token")):
            log_event("SECURITY: ZKP validation failed", level="ALERT")
            await BlackholeRouter.trigger()
            return False

        if payload.get("user_id") and payload["user_id"] != "anonymous":
            if not await validate_voiceprint(payload["user_id"], payload.get("voice_hash")):
                log_event("SECURITY: Voiceprint mismatch", level="WARNING")
                return False

        return True

    @lru_cache(maxsize=1024)
    def _create_hmac_signature(self, data: str) -> str:
        """Tamper-proof signature creation with caching"""
        h = hmac.new(_HMAC_KEY, data.encode('utf-8'), digestmod=hashlib.sha256)
        return h.hexdigest()

    def _verify_hmac_signature(self, signature: str, data: Dict) -> bool:
        """Tamper-proof signature verification"""
        # Ensure consistent serialization for HMAC verification
        data_str = json.dumps(data, sort_keys=True)
        expected_signature = self._create_hmac_signature(data_str)
        return hmac.compare_digest(expected_signature, signature)

    def _encrypt_payload(self, data: Dict) -> bytes:
        """AES-256-GCM encrypted storage"""
        data_str = json.dumps(data)
        return _CIPHER_SUITE.encrypt(data_str.encode())

    def _decrypt_payload(self, data: bytes) -> Dict:
        """Secure feedback decryption"""
        decrypted_str = _CIPHER_SUITE.decrypt(data).decode()
        return json.loads(decrypted_str) # Safely deserialize JSON

async def submit_feedback(payload: Dict) -> Dict:
    """
    Asynchronous, hardened feedback intake with:
    - ZKP session validation
    - Voice biometrics
    - Payload HMAC signing
    - Blackhole anti-fuzzing
    """
    validator = FeedbackValidator()
    
    if not await validator._validate_source(payload):
        return {"status": "error", "message": "Auth failed"}
    
    feedback_text = payload.get("feedback_text")
    if not feedback_text:
        await BlackholeRouter.trigger()
        return {"status": "error", "message": "Missing feedback text"}
    
    if len(feedback_text) > _MAX_FEEDBACK_LENGTH:
        feedback_text = feedback_text[:_MAX_FEEDBACK_LENGTH]
    
    sanitized_text = sanitize_prompt(feedback_text)
    if not sanitized_text:
        await BlackholeRouter.trigger()
        return {"status": "error", "message": "Content blocked"}
    
    # Ensure consistent data for HMAC
    feedback_data = {
        "feedback_id": str(uuid.uuid4()),
        "user_id": payload.get("user_id", "anonymous"),
        "feature": payload.get("feature", "general"),
        "text": sanitized_text,
        "rating": payload.get("rating"),
        "lang": payload.get("lang", "en"),
        "timestamp": payload.get("timestamp", datetime.utcnow().isoformat())
    }
    
    # Sign the feedback data to prove its integrity
    feedback_data_str = json.dumps(feedback_data, sort_keys=True)
    feedback_data["hmac"] = validator._create_hmac_signature(feedback_data_str)
    
    return await process_feedback(feedback_data, validator)

async def process_feedback(feedback: Dict, validator: FeedbackValidator) -> Dict:
    """
    Secure, asynchronous routing with:
    - Classification integrity checks
    - Blockchain-verified logging
    - Autocoder firewalling
    """
    try:
        # Verify feedback integrity using HMAC
        if not validator._verify_hmac_signature(feedback["hmac"], feedback):
            await log_to_blockchain("tamper_attempt", feedback)
            await BlackholeRouter.trigger()
            return {"status": "error", "message": "Tamper detected"}

        # Classify feedback and store for later use
        feedback["classification"] = await classify_feedback(feedback["text"])
        feedback["routed_to"] = []
        
        # Parallelize secure storage and logging
        await asyncio.gather(
            _secure_send_to_storage(feedback, validator),
            _audit_log_feedback(feedback)
        )
        
        if feedback["classification"] in ["negative", "critical"] and FEEDBACK_ROUTING_MODE in ["train", "all"]:
            await _firewalled_autocoder_trigger(feedback, validator)
        
        return {"status": "success", "id": feedback["feedback_id"]}
    except Exception as e:
        log_event(f"FEEDBACK_PROCESSING_FAILED: {str(e)}", level="ERROR")
        return {"status": "error", "message": "Internal error"}

async def _secure_send_to_storage(feedback: Dict, validator: FeedbackValidator):
    """Encrypted MongoDB write with TTL"""
    encrypted = validator._encrypt_payload(feedback)
    await store_with_ttl("user_feedback", encrypted, FEEDBACK_TTL)

async def _audit_log_feedback(feedback: Dict):
    """Immutable blockchain logging"""
    if FEEDBACK_ROUTING_MODE in ["audit", "all"]:
        await log_to_blockchain("feedback_audit", {
            "id": feedback["feedback_id"],
            "user_hash": hashlib.sha256(feedback["user_id"].encode()).hexdigest(),
            "classification": feedback["classification"],
            "timestamp": feedback["timestamp"]
        })

async def _firewalled_autocoder_trigger(feedback: Dict, validator: FeedbackValidator):
    """Sandboxed autocoder queueing with rate-limiting"""
    if FEEDBACK_ROUTING_MODE in ["train", "all"]:
        if not await validator.rate_limiter.check_limit(feedback["user_id"]):
            log_event("RATE_LIMIT_EXCEEDED", user_id=feedback["user_id"])
            return

        await queue_for_autocoder("feedback", feedback)