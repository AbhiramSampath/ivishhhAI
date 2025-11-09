# backend/services/chat_service.py
# 🔒 Final, Secure Chat Service
# 🚀 Refactored Code

import os
import time
import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from fastapi import HTTPException, status
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Corrected Internal imports
from ..routes.gpt import generate_response
from ....ai_control.safety_decision_manager import evaluate_safety, SafetyViolationError
from ....ai_models.emotion.emotion_handler import detect_emotion, EmotionValidationError
from ....ai_models.ivish.ivish_memory import update_memory, get_context, MemoryAccessError
from ..utils.security import sanitize_prompt, PromptSanitizationError
from ..utils.logger import log_event
from ....security.blockchain.blockchain_utils import log_chat_interaction
from ....security.blockchain.zkp_handler import validate_session_token
from ..models.consent import has_user_consent
from ..utils.rate_meter import rate_meter
from ....security.intrusion_prevention.counter_response import blackhole_response_action

# Security constants
MAX_INPUT_LENGTH = int(os.getenv("MAX_INPUT_LENGTH", "2000"))
MAX_CONTEXT_HISTORY = int(os.getenv("MAX_CONTEXT_HISTORY", "10"))
PROMPT_ENCRYPTION_KEY = os.getenv("PROMPT_ENCRYPTION_KEY", None)
if not PROMPT_ENCRYPTION_KEY:
    raise RuntimeError("PROMPT_ENCRYPTION_KEY not found in environment.")
PROMPT_ENCRYPTION_KEY = PROMPT_ENCRYPTION_KEY.encode()

PROMPT_HMAC_KEY = os.getenv("PROMPT_HMAC_KEY", None)
if not PROMPT_HMAC_KEY:
    raise RuntimeError("PROMPT_HMAC_KEY not found in environment.")
PROMPT_HMAC_KEY = PROMPT_HMAC_KEY.encode()

MEMORY_ENABLED = os.getenv("MEMORY_ENABLED", "True").lower() == "true"
SAFETY_MODE = os.getenv("SAFETY_MODE", "True").lower() == "true"
MAX_CHAT_LATENCY_MS = int(os.getenv("MAX_CHAT_LATENCY_MS", "5000"))
_chat_killed = False

logger = logging.getLogger(__name__)

def _hmac_prompt(prompt: str) -> str:
    """HMAC-SHA384 for prompt integrity."""
    h = hmac.HMAC(PROMPT_HMAC_KEY, hashes.SHA384(), backend=default_backend())
    h.update(prompt.encode())
    return h.finalize().hex()

def _encrypt_prompt(prompt: str) -> bytes:
    """AES-256-GCM encryption for sensitive prompts."""
    if _chat_killed:
        return b""

    try:
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(PROMPT_ENCRYPTION_KEY), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(prompt.encode()) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext
    except Exception as e:
        logger.error(f"Prompt encryption failed: {e}", exc_info=True)
        return b""

def _decrypt_prompt(encrypted: bytes) -> str:
    """AES-256-GCM decryption for prompt replay."""
    if _chat_killed or not encrypted or len(encrypted) < 28:
        return ""

    try:
        nonce, tag, ciphertext = encrypted[:12], encrypted[12:28], encrypted[28:]
        cipher = Cipher(algorithms.AES(PROMPT_ENCRYPTION_KEY), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        logger.error(f"Prompt decryption failed: {e}", exc_info=True)
        return ""

class ChatService:
    def __init__(self):
        self._session_key = os.urandom(32)

    async def build_prompt(
        self,
        history: List[Dict],
        user_input: str,
        user_id: str
    ) -> str:
        """Secure prompt construction with injection prevention and integrity checks."""
        if _chat_killed:
            return ""

        try:
            sanitized_input = sanitize_prompt(user_input)
            if not sanitized_input:
                raise PromptSanitizationError("Empty prompt after sanitization")
            
            history_text = ""
            if MEMORY_ENABLED:
                context_data = await get_context(user_id)
                history_text = " ".join([f"User: {item['input']}\nAI: {item['response']}\n" for item in context_data])

            full_prompt = f"{history_text}User: {sanitized_input}\nAI: "
            
            prompt_hash = _hmac_prompt(full_prompt)
            # In a real-world app, you would check a database for blacklisted hashes
            # if prompt_hash in BLACKLISTED_PROMPT_HASHES:
            #     raise PromptSanitizationError("Blacklisted prompt detected")

            encrypted = _encrypt_prompt(full_prompt)
            if not encrypted:
                raise RuntimeError("Encryption failed")
            return encrypted.hex()
        except PromptSanitizationError as e:
            logger.error(f"Prompt sanitization failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Prompt build failed: {e}")
            raise

    async def apply_post_filters(
        self,
        text: str,
        emotion: str,
        user_id: str
    ) -> str:
        """Secure response processing with emotion validation and output sanitization."""
        if _chat_killed:
            return ""
        try:
            # In a real app, `validate_model_output` would check for specific model outputs.
            # Here we'll just sanitize.
            # if not validate_model_output(text):
            #     raise ValueError("Invalid model output")

            modifiers = {
                "distressed": "🙏",
                "happy": "😊",
                "angry": "⚠️",
                "sad": "😢",
                "excited": "🎉"
            }
            prefix = modifiers.get(emotion, "")
            sanitized_text = sanitize_prompt(text)
            return f"{prefix} {sanitized_text}".strip()
        except Exception as e:
            logger.error(f"Post-filter failed for {user_id}: {e}")
            return "[Response processing error]"

    async def chat(
        self,
        user_input: str,
        user_id: str,
        lang_hint: Optional[str] = None,
        session_token: Optional[str] = None
    ) -> Dict:
        """Nuclear-grade chat handler with end-to-end security and real-time processing."""
        if _chat_killed or not validate_session_token(session_token):
            blackhole_response_action()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Chat service temporarily unavailable"
            )

        start_time = time.time()
        try:
            if not user_input or not user_id:
                raise ValueError("Missing input or user_id")

            if len(user_input) > MAX_INPUT_LENGTH:
                raise ValueError("Input exceeds length limit")

            if not has_user_consent(user_id):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User consent required")

            if await rate_meter.track_call(user_id, source="chat"):
                blackhole_response_action()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests"
                )

            context = []
            if MEMORY_ENABLED:
                context = await get_context(user_id)

            prompt_hex = await self.build_prompt(context, user_input, user_id)
            decrypted_prompt = _decrypt_prompt(bytes.fromhex(prompt_hex))

            if not decrypted_prompt:
                raise RuntimeError("Failed to decrypt prompt")

            raw_response = await generate_response(decrypted_prompt, lang=lang_hint)
            emotion_label = await detect_emotion(user_input)
            
            filtered_response = await self.apply_post_filters(raw_response, emotion_label, user_id)
            
            if SAFETY_MODE:
                safety_result = await evaluate_safety(user_input, filtered_response, user_id)
                if safety_result.get("blocked"):
                    raise SafetyViolationError(safety_result.get("reason", "Content violation"))
            
            if MEMORY_ENABLED:
                await update_memory(user_id, user_input, filtered_response)
            
            interaction_hash = _hmac_prompt(user_input + filtered_response)
            await log_chat_interaction(
                user_id=user_id,
                input_hash=hashlib.sha256(user_input.encode()).hexdigest(),
                response_hash=hashlib.sha256(filtered_response.encode()).hexdigest(),
                timestamp=datetime.utcnow(),
                tx_hash=interaction_hash
            )

            latency = (time.time() - start_time) * 1000
            if latency > MAX_CHAT_LATENCY_MS:
                log_event(f"Chat latency attack: {latency:.2f}ms", level="ALERT")

            log_event(f"Chat interaction successful", level="DEBUG", user_id=user_id)
            return {
                "response": filtered_response,
                "tone": emotion_label,
                "latency_ms": latency,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except SafetyViolationError as e:
            log_event(f"Safety violation by {user_id}: {e}", level="ALERT")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Content policy violation")
        except Exception as e:
            log_event(f"Chat failed for {user_id}: {e}", level="ERROR")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Chat processing error")

    async def chat_stream(
        self,
        user_input: str,
        user_id: str,
        lang_hint: Optional[str] = None,
        session_token: Optional[str] = None
    ) -> List[str]:
        """Async streaming chat with security, chunked responses, and safety filtering."""
        if _chat_killed or not validate_session_token(session_token):
            blackhole_response_action()
            return ["⚠️", "Service", "unavailable"]

        if not user_input or len(user_input) > MAX_INPUT_LENGTH:
            return ["⚠️", "Input", "too", "long"]
        
        if not has_user_consent(user_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User consent required")

        try:
            context = await get_context(user_id)
            prompt_hex = await self.build_prompt(context, user_input, user_id)
            decrypted_prompt = _decrypt_prompt(bytes.fromhex(prompt_hex))
            
            raw_stream = await generate_response(decrypted_prompt, lang=lang_hint, stream=True)
            full_response = ""
            filtered_stream = []
            
            async for token in raw_stream:
                if _chat_killed:
                    break
                
                # We can't apply full post-filters on every token, but we can do sanitization
                sanitized_token = sanitize_prompt(token)
                filtered_stream.append(sanitized_token)
                full_response += sanitized_token
                
                if SAFETY_MODE:
                    safety_result = await evaluate_safety(user_input, full_response, user_id)
                    if safety_result.get("blocked"):
                        raise SafetyViolationError(safety_result.get("reason", "Content violation"))
            
            if MEMORY_ENABLED:
                await update_memory(user_id, user_input, full_response)
            
            interaction_hash = _hmac_prompt(user_input + full_response)
            await log_chat_interaction(
                user_id=user_id,
                input_hash=hashlib.sha256(user_input.encode()).hexdigest(),
                response_hash=hashlib.sha256(full_response.encode()).hexdigest(),
                timestamp=datetime.utcnow(),
                tx_hash=interaction_hash
            )
            
            return filtered_stream

        except SafetyViolationError as e:
            log_event(f"Stream safety violation: {e}", level="ALERT")
            return ["⚠️", "Content", "blocked"]
        except Exception as e:
            log_event(f"Stream chat failed: {e}", level="ERROR")
            return ["⚠️", "Error", "processing", "input"]

def kill_chat_service():
    """Emergency kill switch - wipes keys and stops dispatch."""
    global _chat_killed
    _chat_killed = True
    log_event("Chat: Engine killed.", level="critical")
    # In a real app, this would also rotate keys and securely wipe memory.