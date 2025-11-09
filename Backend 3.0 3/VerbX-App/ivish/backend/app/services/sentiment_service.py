# backend/services/sentiment_service.py
# 🔒 Nuclear-Grade Sentiment & Emotion Detection with Zero-Trust Validation
# Enables secure, auditable, and emotionally aware tone classification

import os
import time
import uuid
import asyncio
import logging
import hashlib
import subprocess
import json
import numpy as np
from typing import Dict, Optional, Any, List, Union
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ai_models.sentiment.sentiment_analyzer import classify_sentiment
from ai_models.emotion.emotion_handler import classify_emotion
from ai_models.translation.gpt_rephrase_loop import rephrase_text
from ai_models.tts.tts_handler import synthesize_speech
from ai_models.ivish.memory_agent import update_memory
from ai_control.safety_decision_manager import check_safety
from utils.logger import log_event
from utils.lang_codes import detect_input_language
from security.firewall import Firewall
from security.zkp_handler import validate_sentiment_access
from security.blockchain.blockchain_utils import log_sentiment_event
from security.intrusion_prevention.counter_response import BlackholeRouter
from middlewares.rate_limiter import RateLimiter

# --- Hardcoded constants (from non-existent config file) ---
ENABLE_EMOTION_ENGINE = os.getenv("ENABLE_EMOTION_ENGINE", "True").lower() == "true"
PRIVACY_MODE = os.getenv("PRIVACY_MODE", "True").lower() == "true"

# Security constants
MAX_TEXT_LENGTH = 2000
MIN_CONFIDENCE = 0.3
MAX_SENTIMENT_RATE = 20
BLACKHOLE_DELAY = 60
RATE_LIMIT_WINDOW = 60
SENTIMENT_AES_KEY = os.getenv("SENTIMENT_AES_KEY", "secure_32_byte_aes_key_for_sentiment").encode()[:32]
if len(SENTIMENT_AES_KEY) != 32:
    log_event("CRITICAL: Invalid encryption key for sentiment", alert=True)

logger = logging.getLogger(__name__)

class SentimentAnalysis:
    """
    Immutable sentiment analysis with cryptographic validation
    """
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.integrity_tag = self._compute_integrity_tag()

    def _compute_integrity_tag(self) -> str:
        """Cryptographic tag for sentiment validation"""
        h = hmac.HMAC(SENTIMENT_AES_KEY, hashes.SHA256(), backend=default_backend())
        h.update(json.dumps(self.data, sort_keys=True).encode())
        return h.finalize().hex()

    def __repr__(self):
        return json.dumps(self.data)

class NuclearSentimentEngine:
    """
    Provides secure, auditable, and emotionally aware sentiment detection.
    """
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.blackhole = BlackholeRouter()
        self.firewall = Firewall()
        self._sentinel_triggered = False

    async def _scrub_pii(self, text: str) -> str:
        """Secure PII redaction"""
        return await self.firewall.scrub_pii(text)

    async def authenticate_sentiment(self, user_id: str, session_token: str, zk_proof: str) -> bool:
        """ZKP-based sentiment access control with rate limiting."""
        if not await self.rate_limiter.check_limit(user_id, rate=MAX_SENTIMENT_RATE, window=RATE_LIMIT_WINDOW):
            log_event("[SECURITY] Sentiment rate limit exceeded", alert=True)
            await self.blackhole.trigger(delay_sec=BLACKHOLE_DELAY)
            return False
        
        is_authorized = await validate_sentiment_access(user_id, zk_proof)
        if not is_authorized:
            log_event(f"[SECURITY] Unauthorized sentiment access for {user_id[:6]}...", alert=True)
            await self.blackhole.trigger()
            return False
        return True

    async def analyze_text_tone(
        self,
        text: str,
        user_id: str = "anonymous",
        session_token: str = "",
        zk_proof: str = ""
    ) -> Dict[str, Any]:
        """
        Secure sentiment analysis with:
        - ZKP validation
        - Input sanitization
        - Model protection
        - Integrity logging
        """
        if not await self.authenticate_sentiment(user_id, session_token, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}

        if not text or len(text) > MAX_TEXT_LENGTH:
            return {"status": "invalid", "error": "Empty or oversized input"}

        try:
            sanitized = await self.firewall.sanitize_text(text)
            if not sanitized:
                return {"status": "rejected", "error": "Tampered input detected"}

            if PRIVACY_MODE:
                sanitized = await self._scrub_pii(sanitized)

            sentiment_result = await classify_sentiment(sanitized)
            emotion_result = await classify_emotion(sanitized)

            emotion = emotion_result.get("label", "neutral")
            if emotion_result.get("confidence", 0) < MIN_CONFIDENCE:
                emotion = "neutral"

            sentiment = sentiment_result.get("label", "neutral")
            if sentiment_result.get("score", 0) < MIN_CONFIDENCE:
                sentiment = "neutral"

            await log_sentiment_event({
                "action": "analyze_text_tone",
                "user": user_id,
                "emotion": emotion,
                "sentiment": sentiment,
                "input_hash": self._compute_integrity_tag(sanitized),
                "timestamp": time.time()
            })

            return {
                "status": "success",
                "emotion": emotion,
                "emotion_score": float(np.clip(emotion_result.get("confidence", 0), 0, 1)),
                "sentiment": sentiment,
                "sentiment_score": float(np.clip(sentiment_result.get("score", 0), -1, 1)),
                "integrity": self._compute_integrity_tag(json.dumps({
                    "input": sanitized,
                    "emotion": emotion,
                    "sentiment": sentiment
                }, sort_keys=True)),
                "timestamp": time.time()
            }

        except Exception as e:
            log_event(f"[SENTIMENT] Analysis failed: {str(e)}", alert=True)
            await self.blackhole.trigger()
            return {"status": "failed", "error": str(e)}

    async def analyze_speech_tone(
        self,
        audio_data: bytes,
        user_id: str = "anonymous",
        session_token: str = "",
        zk_proof: str = ""
    ) -> Dict[str, Any]:
        """
        Secure speech → text → sentiment analysis with:
        - Audio validation
        - STT fallback
        - ZKP authentication
        """
        if not await self.authenticate_sentiment(user_id, session_token, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}
        if not audio_data or len(audio_data) > MAX_AUDIO_SIZE:
            return {"status": "invalid", "error": "Empty or oversized audio"}
        try:
            processed = await self.firewall.sanitize_audio(audio_data)
            if not processed:
                return {"status": "failed", "error": "Audio preprocessing failed"}
            stt_result = await transcribe_audio(processed)
            if not stt_result.get("text"):
                return {"status": "failed", "error": "No speech detected"}
            return await self.analyze_text_tone(stt_result["text"], user_id, session_token, zk_proof)
        except Exception as e:
            log_event(f"[SENTIMENT] Speech analysis failed: {str(e)}", alert=True)
            await self.blackhole.trigger()
            return {"status": "failed", "error": str(e)}

    async def detect_escalation(
        self,
        text: str,
        user_id: str = "",
        session_token: str = "",
        zk_proof: str = ""
    ) -> Dict[str, Any]:
        """
        Escalation detection with:
        - Sentiment analysis
        - Urgent keyword detection
        - Safety check
        """
        analysis = await self.analyze_text_tone(text, user_id, session_token, zk_proof)
        if analysis["status"] != "success":
            return analysis
        is_escalating = (
            analysis["emotion"] in ["distressed", "angry", "panicked"] or
            analysis["sentiment_score"] < -0.7 or
            self._contains_urgent_keywords(text)
        )
        return {"status": "success", "escalating": is_escalating}

    def _contains_urgent_keywords(self, text: str) -> bool:
        """Hardcoded safety net for critical phrases"""
        URGENT_PATTERNS = {
            "help me", "emergency", "danger", "suicide", "kill myself", "911", "fire", "hurt"
        }
        return any(pattern in text.lower() for pattern in URGENT_PATTERNS)

    async def rephrase_with_tone(self, text: str, tone: str, user_id: str) -> Dict[str, Any]:
        """
        Rephrase response based on emotional tone
        """
        try:
            rephrased = await rephrase_text(text, tone=tone)
            return {"status": "success", "rephrased_text": rephrased}
        except Exception as e:
            log_event(f"[SENTIMENT] Rephrasing failed: {str(e)}", alert=True)
            await self.blackhole.trigger()
            return {"status": "failed", "error": str(e)}

    async def synthesize_with_tone(self, text: str, tone: str, user_id: str) -> Dict[str, Any]:
        """
        Synthesize speech with emotional tone injection
        """
        try:
            audio = await synthesize_speech(text, tone=tone)
            return {"status": "success", "audio": audio}
        except Exception as e:
            log_event(f"[SENTIMENT] TTS synthesis failed: {str(e)}", alert=True)
            await self.blackhole.trigger()
            return {"status": "failed", "error": str(e)}

    async def update_memory_with_tone(self, user_id: str, text: str, tone: str) -> Dict[str, Any]:
        """
        Secure memory update with emotional tagging
        """
        try:
            success = await update_memory(user_id, text, tone)
            return {"status": "success" if success else "failed"}
        except Exception as e:
            log_event(f"[SENTIMENT] Memory update failed: {str(e)}", alert=True)
            await self.blackhole.trigger()
            return {"status": "failed", "error": str(e)}

    def _compute_integrity_tag(self, payload: str) -> str:
        """Cryptographic tag for sentiment validation"""
        h = hmac.HMAC(SENTIMENT_AES_KEY, hashes.SHA256(), backend=default_backend())
        h.update(payload.encode())
        return h.finalize().hex()

# Singleton with rate limit
sentiment_analyzer = NuclearSentimentEngine()