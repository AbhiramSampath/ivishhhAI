# backend/services/ivish_service.py
# 🔒 Nuclear-Grade AI Pipeline Orchestrator with Zero-Trust Validation
# Central orchestrator for Ivish AI — STT → Emotion → GPT → Rephrase → TTS

import os
import time
import uuid
import asyncio
import logging
import hashlib
import subprocess
import json
from typing import Dict, Optional, Any, List, Union
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac

# Security imports - CORRECTED PATHS
from security.voice_biometric_auth import validate_voiceprint
from security.firewall import Firewall
from security.blockchain.zkp_handler import validate_pipeline_access
from security.blockchain.blockchain_utils import log_pipeline_event
from security.intrusion_prevention.counter_response import BlackholeRouter
from middlewares.rate_limiter import RateLimiter

# AI module imports - CORRECTED PATHS
from ai_models.whisper.whisper_handler import transcribe_audio
from ai_models.translation.mt_translate import translate_text
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.gpt_rephrase_loop import rephrase_text
from ai_models.ivish.memory_agent import update_memory, fetch_memory
from ivish_central.agent_router import RATE_LIMIT_WINDOW, route_prompt
from ai_models.tts.tts_handler import synthesize_speech

# Auth & session - CORRECTED PATHS
from security.jwt_handler import validate_token
from utils.logger import log_event
from utils.lang_codes import detect_input_language

logger = logging.getLogger(__name__)

# --- Hardcoded constants (from assumed config file) ---
ENABLE_TRANSLATION = os.getenv("ENABLE_TRANSLATION", "True").lower() == "true"
ENABLE_TTS = os.getenv("ENABLE_TTS", "True").lower() == "true"
MAX_PIPELINE_RATE = int(os.getenv("MAX_PIPELINE_RATE", 100))
PRIVACY_MODE = os.getenv("PRIVACY_MODE", "True").lower() == "true"

# Security constants
MAX_INPUT_LENGTH = 2000  # Prevent DoS
MAX_AUDIO_SIZE = 2 * 1024 * 1024  # 2MB
BLACKHOLE_DELAY = 60  # Seconds to delay attacker
TEMP_PIPELINE_PATHS = ["/tmp/ivish_pipeline_*", "/dev/shm/pipeline_*"]

# AES-256-GCM encryption key from environment variables
PIPELINE_AES_KEY = os.getenv("PIPELINE_AES_KEY", "").encode()[:32]
if len(PIPELINE_AES_KEY) != 32:
    log_event("CRITICAL: Invalid encryption key for AI pipeline", alert=True)

class PipelineResponse:
    """
    Immutable pipeline response with cryptographic validation
    """
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.integrity_tag = self._compute_integrity_tag()
        self._secure_wipe_temp(data.get("audio_path"))

    def _compute_integrity_tag(self) -> str:
        """Cryptographic tag for pipeline validation"""
        h = hmac.HMAC(PIPELINE_AES_KEY, hashes.SHA256())
        h.update(json.dumps(self.data, sort_keys=True).encode())
        return h.finalize().hex()

    def _secure_wipe_temp(self, path: Optional[str]):
        """Securely wipe temporary pipeline files"""
        if path and os.path.exists(path):
            try:
                subprocess.run(['shred', '-u', path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error(f"Secure wipe failed for {path}: {e}")

    def __repr__(self):
        return json.dumps(self.data)

class NuclearPipelineOrchestrator:
    """
    Provides secure, auditable, and real-time AI orchestration.
    """
    def __init__(self):
        self.firewall = Firewall()
        self.rate_limiter = RateLimiter()
        self.blackhole = BlackholeRouter()

    async def _validate_rate_limit(self, user_id: str) -> bool:
        """Prevent pipeline flooding attacks using scalable middleware."""
        is_limited = not await self.rate_limiter.check_limit(user_id, rate=MAX_PIPELINE_RATE, window=RATE_LIMIT_WINDOW)
        if is_limited:
            log_event("[SECURITY] Pipeline rate limit exceeded", alert=True)
            await self.blackhole.trigger(delay_sec=BLACKHOLE_DELAY)
        return not is_limited

    def _compute_integrity_tag(self, payload: Union[str, Dict[str, Any]]) -> str:
        """Cryptographic tag for pipeline validation"""
        if isinstance(payload, Dict):
            payload = json.dumps(payload, sort_keys=True)
        h = hmac.HMAC(PIPELINE_AES_KEY, hashes.SHA256())
        h.update(payload.encode())
        return h.finalize().hex()

    def _hash_user_id(self, user_id: str) -> str:
        """PBKDF2-HMAC-SHA512 user hashing"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=b"pipeline_user_salt_2023",
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(user_id.encode()).hex()

    async def authenticate_pipeline(self, user_id: str, session_token: str, zk_proof: str) -> bool:
        """ZKP-based pipeline access control with rate limiting."""
        if not await self._validate_rate_limit(user_id):
            return False
        
        is_authorized = validate_pipeline_access(user_id, zk_proof)
        if not is_authorized:
            log_event(f"[SECURITY] Unauthorized pipeline access for {user_id[:6]}...", alert=True)
            await self.blackhole.trigger()
            return False

        if not await validate_token(user_id, session_token):
            self.firewall.log_breach_attempt(user_id)
            return False

        return True

    async def process_voice_request(
        self,
        audio_data: bytes,
        user_id: str,
        target_lang: str = "en",
        session_token: str = "",
        zk_proof: str = ""
    ) -> Dict[str, Any]:
        """
        Secure voice processing pipeline with:
        - ZKP validation
        - Audio sanitization
        - STT → TTS → emotion loop
        """
        if not await self.authenticate_pipeline(user_id, session_token, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}

        if not audio_data or len(audio_data) > MAX_AUDIO_SIZE:
            return {"status": "invalid", "error": "Empty or oversized audio"}

        try:
            # 1. Audio validation
            sanitized_audio = await self.firewall.sanitize_audio(audio_data)
            if not sanitized_audio:
                return {"status": "rejected", "error": "Tampered audio detected"}
            
            # 2. Voice biometrics check
            if not await validate_voiceprint(user_id, audio_data):
                return {"status": "auth_failed", "error": "Invalid voiceprint"}

            # 3. STT
            stt_result = await transcribe_audio(sanitized_audio)
            if not stt_result.get("text"):
                return {"status": "empty", "error": "No speech detected"}
            
            # 4. Language detection and translation
            src_lang = stt_result.get("language", "en")
            translated_text = stt_result["text"]
            if ENABLE_TRANSLATION and src_lang != target_lang:
                translated_text = await translate_text(stt_result["text"], src=src_lang, tgt=target_lang)

            # 5. Emotion detection
            emotion = await detect_emotion(translated_text)

            # 6. GPT routing and memory
            memory_context = await fetch_memory(user_id)
            gpt_prompt = f"[Tone: {emotion}] [Lang: {target_lang}] {memory_context}\nUser: {translated_text}"
            gpt_response = await route_prompt(gpt_prompt, user_id)

            # 7. Rephrase and TTS
            rephrased = await rephrase_text(gpt_response, tone=emotion)
            audio_output = await synthesize_speech(rephrased, lang=target_lang, tone=emotion) if ENABLE_TTS else None

            # 8. Secure memory update
            asyncio.create_task(update_memory(user_id, stt_result["text"], rephrased))

            # 9. Blockchain audit
            await log_pipeline_event({
                "action": "voice_pipeline",
                "user_id": self._hash_user_id(user_id),
                "src_lang": src_lang,
                "tgt_lang": target_lang,
                "emotion": emotion,
                "timestamp": time.time(),
                "input_hash": self._compute_integrity_tag(stt_result["text"]),
                "output_hash": self._compute_integrity_tag(rephrased)
            })

            return PipelineResponse({
                "status": "success",
                "audio": audio_output,
                "caption": rephrased,
                "emotion": emotion,
                "transcript": stt_result["text"],
                "integrity": self._compute_integrity_tag({"input": stt_result["text"], "output": rephrased})
            }).data

        except Exception as e:
            log_event(f"[PIPELINE] Voice pipeline failed: {str(e)}", alert=True)
            await self.blackhole.trigger()
            return {"status": "failed", "error": str(e)}

    async def process_text_request(
        self,
        user_input: str,
        user_id: str,
        target_lang: str = "en",
        session_token: str = "",
        zk_proof: str = ""
    ) -> Dict[str, Any]:
        """
        Secure text processing pipeline with:
        - ZKP validation
        - Input sanitization
        - Emotion detection
        - Memory injection
        - Secure logging
        """
        if not await self.authenticate_pipeline(user_id, session_token, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}

        if not user_input or len(user_input) > MAX_INPUT_LENGTH:
            return {"status": "invalid", "error": "Empty or oversized input"}
        
        try:
            # 1. Input sanitization
            sanitized_input = await self.firewall.sanitize_text(user_input)
            if not sanitized_input:
                return {"status": "rejected", "error": "Tampered input"}
            
            # 2. Emotion detection
            emotion = await detect_emotion(sanitized_input)

            # 3. Translation
            translated_input = sanitized_input
            if ENABLE_TRANSLATION:
                translated_input = await translate_text(sanitized_input, tgt=target_lang)

            # 4. GPT routing
            memory_context = await fetch_memory(user_id)
            gpt_prompt = f"[Tone: {emotion}] [Lang: {target_lang}] {memory_context}\nUser: {translated_input}"
            gpt_response = await route_prompt(gpt_prompt, user_id)

            # 5. Rephrasing & TTS
            rephrased = await rephrase_text(gpt_response, tone=emotion)
            audio_output = await synthesize_speech(rephrased, lang=target_lang, tone=emotion) if ENABLE_TTS else None

            # 6. Secure memory update
            asyncio.create_task(update_memory(user_id, sanitized_input, rephrased))

            # 7. Blockchain audit
            await log_pipeline_event({
                "action": "text_pipeline",
                "user_id": self._hash_user_id(user_id),
                "src_lang": "en",
                "tgt_lang": target_lang,
                "emotion": emotion,
                "timestamp": time.time(),
                "input_hash": self._compute_integrity_tag(sanitized_input),
                "output_hash": self._compute_integrity_tag(rephrased)
            })

            return PipelineResponse({
                "status": "success",
                "audio": audio_output,
                "caption": rephrased,
                "emotion": emotion,
                "original": sanitized_input,
                "integrity": self._compute_integrity_tag({"input": sanitized_input, "output": rephrased})
            }).data

        except Exception as e:
            log_event(f"[PIPELINE] Text pipeline failed: {str(e)}", alert=True)
            await self.blackhole.trigger()
            return {"status": "failed", "error": str(e)}

    async def summarize_session(self, user_id: str, session_token: str = "", zk_proof: str = "") -> Dict[str, Any]:
        """
        Privacy-preserving session summary with ZKP validation
        """
        if not await self.authenticate_pipeline(user_id, session_token, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}
        
        try:
            context = await fetch_memory(user_id)
            sanitized_context = await self.firewall.scrub_pii(context)
            summary = await route_prompt(
                f"Summarize this session without PII: {sanitized_context}",
                user_id
            )
            return {
                "status": "success",
                "summary": summary,
                "timestamp": time.time()
            }
        except Exception as e:
            log_event(f"[PIPELINE] Session summary failed: {str(e)}", alert=True)
            await self.blackhole.trigger()
            return {"status": "failed", "error": str(e)}

# Singleton with rate limit
pipeline_orchestrator = NuclearPipelineOrchestrator()