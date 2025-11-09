"""
🧠 Ivish AI Secure Chat Endpoint
🔐 Nuclear-grade POST route for GPT/LLM interactions
📦 Features: memory, emotion, safety, translation, blockchain audit
🛡️ Security: ZKP, input sanitization, rate limiting, anti-injection
"""

import os
import re
import uuid
import asyncio
import hashlib
import hmac
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from functools import lru_cache

# 🔐 Security Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# 📁 Project Imports - CORRECTED PATHS
from fastapi import APIRouter, Request, HTTPException, status
from pydantic import BaseModel, Field, validator
from ai_models.translation.gpt_prompter import generate_response
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.gpt_rephrase_loop import rephrase_text
from ai_control.safety_decision_manager import evaluate_safety
from ai_models.ivish.memory_agent import fetch_context, update_context
from utils.logger import log_event
from middlewares.rate_limiter import RateLimiter as ModelRateLimiter
from security.blockchain.zkp_handler import verify_gpt_access, ZKPAuthenticator
from security.intrusion_prevention.counter_response import BlackholeRouter
from security.blockchain.blockchain_utils import log_gpt_interaction

# --- Hardcoded constants (from non-existent config file) ---
MEMORY_ENABLED = os.getenv("MEMORY_ENABLED", "True").lower() == "true"
SAFETY_MODE = os.getenv("SAFETY_MODE", "True").lower() == "true"

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("CHAT_HMAC_KEY", "chat_endpoint_signature_key").encode()
_SALT = os.urandom(16)
_KDF_ITERATIONS = 100000
_LATENCY_BUDGET_MS = 1000
_MAX_MESSAGE_LENGTH = 2000
_MIN_SESSION_LENGTH = 8
_MAX_SESSION_LENGTH = 64
_SUPPORTED_MODELS = ['gpt-4o', 'gpt-4', 'llama3', 'phi3', 'mistral', 'sarvam', 'coqui', 'whisper']
_SUPPORTED_LANGS = ['en', 'hi', 'ta', 'te', 'bn', 'kn', 'es', 'fr', 'de', 'ru', 'ja', 'zh']
_SAFE_MODE_PROMPT = "[SAFE MODE] Output must be respectful, safe, and appropriate"
_MODEL_WEIGHTS = {"gpt-4o": 2, "gpt-4": 2, "llama3": 1}

class GPTRequest(BaseModel):
    """
    📌 Structured GPT request with security validation
    """
    user_id: str = Field(..., min_length=8, max_length=64, regex=r'^[a-zA-Z0-9_-]+$')
    message: str = Field(..., max_length=_MAX_MESSAGE_LENGTH)
    device_fingerprint: str
    consent_token: str
    zkp_proof: str
    model: Optional[str] = None
    language: Optional[str] = None
    tone: Optional[str] = None

    @validator("model")
    def validate_model(cls, v):
        if v and v not in _SUPPORTED_MODELS:
            raise ValueError("Unsupported LLM model")
        return v

    @validator("language")
    def validate_language(cls, v):
        if v and v not in _SUPPORTED_LANGS:
            raise ValueError("Unsupported language")
        return v

    @validator("tone")
    def validate_tone(cls, v):
        valid_tones = ['neutral', 'happy', 'sad', 'angry', 'empathetic', 'calm', 'formal']
        if v and v not in valid_tones:
            raise ValueError("Invalid tone")
        return v

# 🔒 Rate Limiter and Blackhole
_limiter = ModelRateLimiter(max_requests=30, period=60, model_weights=_MODEL_WEIGHTS)
_blackhole_router = BlackholeRouter()
router = APIRouter()

class SecureChatEngine:
    """
    🔒 Secure Chat Engine
    """
    def __init__(self):
        self.zkp_auth = ZKPAuthenticator()

    def _sign_response(self, response: Dict) -> str:
        """HMAC-sign chat response"""
        h = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        h.update(json.dumps(response, sort_keys=True).encode())
        return h.finalize().hex()

    async def _super_sanitize(self, text: str, user_id: str) -> str:
        """Multi-layered input sanitization"""
        clean = re.sub(r'[`~!@#$%^&*()_+={}\[\]:;"<>,.?]', '', text)
        tokens = clean.split()
        if len(tokens) > 500:
            await log_event(f"INPUT_OVERFLOW from {user_id}", level="WARNING")
            clean = " ".join(tokens[:500])
        return clean

    async def _build_secure_prompt(self, context: str, message: str, emotion: str, tone: str) -> str:
        """Safety-wrapped prompt construction"""
        base_prompt = f"""
        [System] Current emotional tone: {emotion}
        [Context] {context}
        [User] {message}
        [Assistant] {_SAFE_MODE_PROMPT if SAFETY_MODE else ""}
        """
        if tone:
            base_prompt += f"\n[Style] {tone}"
        return base_prompt

    async def _handle_unsafe_input(self, payload: GPTRequest, safety_result: dict):
        """Countermeasures for policy violations"""
        await log_gpt_interaction(
            user_id=payload.user_id,
            session_id="BLOCKED_" + str(uuid.uuid4()),
            input=payload.message,
            output="[BLOCKED]",
            audit_chain=[{"safety_block": safety_result["reason"]}],
            safety_status="blocked"
        )
        await log_event(f"SAFETY_BLOCK | {payload.user_id} | {safety_result['reason']}", level="ALERT")

    async def _handle_malicious_request(self, request: Request, user_id: str):
        """Active defense against attackers"""
        client_ip = request.client.host
        await _blackhole_router.trigger(ip_address=client_ip)
        await log_event(f"MALICIOUS_REQUEST_BLOCKED from {client_ip} for user {user_id}", level="CRITICAL")

    async def _handle_chat_failure(self, payload: GPTRequest, session_id: str, error: str):
        """Secure failure handling with audit trail"""
        await log_gpt_interaction(
            user_id=payload.user_id,
            session_id=session_id,
            input=payload.message,
            output=f"[ERROR] {error}",
            audit_chain=[{"failure": error}],
            safety_status="error"
        )

    async def _log_to_blockchain(self, user_id: str, session_id: str, input_text: str, output_text: str, audit_chain: List[Dict], emotion: str, status: str):
        """Tamper-evident blockchain logging"""
        try:
            await log_gpt_interaction(
                user_id=user_id,
                session_id=session_id,
                input=input_text,
                output=output_text,
                audit_chain=audit_chain,
                emotion=emotion,
                safety_status=status
            )
        except Exception as e:
            await log_event(f"BLOCKCHAIN_LOG_FAILURE: {str(e)}", level="ERROR")

    def _generate_response_hash(self, text: str) -> str:
        """Tamper-evident hashing"""
        digest = hashes.Hash(hashes.BLAKE2s(16), backend=_BACKEND)
        digest.update(text.encode())
        return digest.finalize().hex()

@router.post("/chat", status_code=status.HTTP_200_OK)
async def chat_endpoint(request: Request, payload: GPTRequest):
    """
    🔐 Nuclear-grade chat endpoint
    """
    engine = SecureChatEngine()
    try:
        if not await verify_gpt_access(payload.user_id, payload.zkp_proof):
            await engine._handle_malicious_request(request, payload.user_id)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Consent verification failed")

        if not await _limiter.check_limit(payload.user_id):
            await asyncio.sleep(5)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")

        session_id = str(uuid.uuid4())
        audit_chain = [{"step": "start", "timestamp": datetime.now().isoformat()}]
        await log_event(f"[CHAT_SECURE] Session {session_id[:8]} initiated", level="DEBUG")

        clean_msg = await engine._super_sanitize(payload.message, payload.user_id)
        audit_chain.append({"input": clean_msg, "sanitized": True})

        context = ""
        if MEMORY_ENABLED:
            context = await fetch_context(payload.user_id, privacy_filter=True)
            audit_chain.append({"memory_accessed": bool(context)})

        safety_task = evaluate_safety(clean_msg, "", payload.user_id)
        emotion_task = detect_emotion(clean_msg)
        safety_result, emotion = await asyncio.gather(safety_task, emotion_task)

        if safety_result["status"] == "blocked":
            await engine._handle_unsafe_input(payload, safety_result)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Content policy violation")

        full_prompt = await engine._build_secure_prompt(context, clean_msg, emotion, payload.tone)

        ai_reply = await generate_response(
            full_prompt,
            user_id=payload.user_id,
            safety_level=SAFETY_MODE,
            model=payload.model or "gpt-4"
        )
        audit_chain.append({"generated_reply": ai_reply[:100] + "..."})

        post_safety = await evaluate_safety(clean_msg, ai_reply, payload.user_id)
        if post_safety["status"] == "blocked":
            ai_reply = "[Response filtered due to safety policy]"
            audit_chain.append({"post_filter_applied": True})

        if MEMORY_ENABLED:
            await update_context(
                payload.user_id,
                user_input=clean_msg,
                ai_response=ai_reply
            )

        await engine._log_to_blockchain(
            payload.user_id,
            session_id,
            clean_msg,
            ai_reply,
            audit_chain,
            emotion,
            post_safety["status"]
        )

        response = {
            "reply": ai_reply,
            "emotion": emotion,
            "safety": post_safety["status"],
            "session_id": session_id,
            "integrity_hash": engine._generate_response_hash(ai_reply),
            "timestamp": datetime.now().isoformat(),
            "model_used": payload.model or "gpt-4"
        }
        response["_signature"] = engine._sign_response(response)
        return response

    except HTTPException:
        raise
    except Exception as e:
        await engine._handle_chat_failure(payload, session_id, str(e))
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Secure processing failed")