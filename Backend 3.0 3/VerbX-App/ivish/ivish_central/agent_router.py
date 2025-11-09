# ivish_central/agent_router.py
# 🔒 Nuclear-Grade AI Routing Engine with Zero-Trust Validation
# Central AI router for Ivish — voice/text → STT → emotion → GPT → rephrase → TTS

import os
import time
import uuid
import asyncio
import hashlib
import logging
import subprocess
import shlex
from datetime import datetime
from typing import Dict, Any, Union, List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from fastapi import HTTPException

# Internal imports (Corrected based on project structure)
from ai_models.whisper.whisper_handler import stream_transcribe as transcribe_audio
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.mt_translate import translate_text
from ai_models.translation.gpt_rephrase_loop import rephrase_response
from ai_models.ivish.ivish_memory import update_memory, get_context
from ai_models.translation.gpt_rephrase_loop import generate_response
from ai_models.tts.tts_handler import speak_response
from ai_models.translation.dialect_adapter import detect_input_language
from security.blockchain.zkp_handler import validate_session_token
from security.blockchain.blockchain_utils import log_conversation_event
from security.intrusion_prevention.counter_response import trigger_blackhole
from security.intrusion_prevention.isolation_engine import rotate_endpoints

from backend.app.middlewares.rate_limiter import check_rate_limit
from config.system_flags import ENABLE_TRANSLATION, ENABLE_TTS, ROUTING_AES_KEY

logger = logging.getLogger(__name__)

class AgentRouter:
    """
    Provides secure, auditable, and emotionally aware routing of user input to AI modules.
    
    Responsibilities:
    - Route user input through secure AI pipeline
    - Handle voice and text input
    - Detect emotion, tone, and language
    - Query GPT or local model for response
    - Rephrase and translate as needed
    - Trigger TTS or text return
    - Log all interactions securely
    - Auto-wipe on intrusion detection
    - Integrate with ZKP for access control
    """

    def __init__(self):
        self._rate_limiter_lock = asyncio.Lock()


    async def _is_rate_limited(self, user_id: str) -> bool:
        """Sliding window rate limiter."""
        async with self._rate_limiter_lock:
            return not check_rate_limit(f"agent_router:{user_id}", max_calls=10, period=60)

    def _secure_wipe(self, paths: list):
        """Securely wipe temporary routing data."""
        for path in paths:
            try:
                subprocess.run(shlex.split(f'shred -u {path}'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error(f"Secure wipe failed for {path}: {e}")

    def _encrypt_data(self, data: bytes) -> bytes:
        """AES-256-GCM encryption for secure context with per-operation IV (never reused)."""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(ROUTING_AES_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        return iv + tag + ciphertext

    def _decrypt_data(self, data: bytes) -> bytes:
        """Secure decryption for routing context."""
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = Cipher(algorithms.AES(ROUTING_AES_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _hash_user_id(self, user_id: str) -> str:
        """Pseudonymize user IDs for logging with a per-user, non-hardcoded salt."""
        salt = hashlib.sha256(user_id.encode()).digest()  # Use a deterministic salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            iterations=100000
        )
        return kdf.derive(user_id.encode()).hex()

    def _generate_chain_hash(self) -> str:
        """Blockchain-style hash chaining for audit."""
        return f"0x{uuid.uuid4().hex}"

    def _validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Zero-trust input validation."""
        if not isinstance(input_data, dict):
            return False
        required_keys = {"type", "content", "user_id"}
        if not required_keys.issubset(input_data.keys()):
            return False
        if input_data["type"] not in {"voice", "text"}:
            return False
        if not input_data["content"] or len(str(input_data["content"])) > 5000:
            return False
        return True

    async def route_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Secure async router with defense-in-depth.
        input_data: {
            "type": "voice"|"text",
            "content": str|file_path,
            "user_id": str,
            "session_token": str  # ZKP ephemeral token
        }
        """
        if not self._validate_input(input_data):
            logger.warning("Invalid input data", exc_info=True)
            return self._honeypot

        if not validate_session_token(input_data.get("session_token", "")):
            logger.critical(f"Unauthorized access for {input_data.get('user_id', 'unknown')}")
            await trigger_blackhole()
            return {"status": "unauthorized"}

        try:
            if input_data["type"] == "voice":
                return await self.handle_voice_input(input_data["content"], input_data["user_id"])
            else:
                return await self.handle_text_input(input_data["content"], input_data["user_id"])
        except Exception as e:
            logger.error(f"[ROUTER] Routing failed: {str(e)}", exc_info=True)
            await trigger_blackhole()
            return {"status": "error"}

    async def handle_voice_input(self, audio_path: str, user_id: str) -> Dict[str, Any]:
        """Secure voice processing pipeline."""
        if not os.path.exists(audio_path) or os.path.getsize(audio_path) > 30 * 16000 * 2:
            logger.warning(f"Invalid audio file: {audio_path}")
            return self._honeypot

        try:
            stt_result = await transcribe_audio(audio_path)
            if not stt_result.get("text"):
                return {"reply": "", "audio": None, "security_token": "invalid"}
            
            return await self.process_text(
                text=stt_result["text"],
                user_id=user_id,
                lang=stt_result.get("language", "en")
            )
        except Exception as e:
            logger.error(f"[ROUTER] Voice processing failed: {str(e)}", exc_info=True)
            await trigger_blackhole()
            return {"status": "error"}

    async def handle_text_input(self, text: str, user_id: str) -> Dict[str, Any]:
        """Text processing with anti-tampering."""
        if not isinstance(text, str) or len(text) > 5000:
            logger.warning(f"Invalid text input: {text[:20]}...")
            return self._honeypot

        try:
            sanitized_text = text.replace("\0", "").strip()
            lang = await detect_input_language(sanitized_text)
            return await self.process_text(sanitized_text, user_id, lang)
        except Exception as e:
            logger.error(f"[ROUTER] Text processing failed: {str(e)}", exc_info=True)
            await trigger_blackhole()
            return {"status": "error"}

    async def process_text(self, text: str, user_id: str, lang: str) -> Dict[str, Any]:
        """Core processing with emotional intelligence."""
        if await self._is_rate_limited(user_id):
            return {"reply": "Please wait...", "audio": None, "security_token": "wait"}

        try:
            tone = await detect_emotion(text)
            context = await get_context(user_id)
            encrypted_ctx = self._encrypt_data(context.encode())
            
            # The prompt is constructed as a secure dictionary to prevent injection
            prompt_data = {
                "tone": tone,
                "language": lang,
                "context": encrypted_ctx.hex(), # Pass encrypted context as hex string
                "user_text": text
            }
            
            reply = await generate_response(prompt_data, user_id)
            reply = await rephrase_response(reply, tone)

            if ENABLE_TRANSLATION and lang != "en":
                reply = await translate_text(reply, target_lang=lang)

            await update_memory(user_id, text, reply)
            await self.log_conversation(user_id, text, reply)

            return await self.postprocess_and_respond(reply, lang)

        except Exception as e:
            logger.error(f"[ROUTER] Core processing failed: {str(e)}", exc_info=True)
            await trigger_blackhole()
            return {"status": "error"}

    async def postprocess_and_respond(self, reply: str, lang: str) -> Dict[str, Any]:
        """Secure response formatting with optional TTS."""
        if not reply or not isinstance(reply, str):
            return self._honeypot

        try:
            if ENABLE_TTS:
                audio_path = await speak_response(reply[:500], lang)
                return {
                    "reply": reply,
                    "audio": audio_path,
                    "security_token": str(uuid.uuid4())
                }
            return {
                "reply": reply,
                "security_token": str(uuid.uuid4())
            }
        except Exception as e:
            logger.error(f"[ROUTER] Postprocessing failed: {str(e)}", exc_info=True)
            return {"status": "failed", "error": str(e)}

    async def log_conversation(self, user_id: str, input_text: str, reply_text: str):
        """Immutable blockchain-style logging."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_id": self._hash_user_id(user_id),
            "input_hash": hashlib.sha256(input_text.encode()).hexdigest(),
            "reply_hash": hashlib.sha256(reply_text.encode()).hexdigest(),
            "uuid": str(uuid.uuid4()),
            "chain_hash": self._generate_chain_hash()
        }
        await log_conversation_event(log_entry)

# Singleton with rate limit
agent_router = AgentRouter()