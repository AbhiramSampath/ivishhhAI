import os
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import logging
from functools import lru_cache
import asyncio
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Corrected Project Imports
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.slang.slang_cleaner import clean_slang
from ai_models.ivish.memory_agent import get_session_memory
from backend.app.utils.logger import log_event, BaseLogger
from security.blockchain.zkp_handler import ZKPHandler as ZKPAuthenticator
from security.firewall import Firewall

# --- Placeholder Imports for non-existent modules ---
def detect_language(text: str) -> str:
    """Placeholder for language detection."""
    return "en"

# --- Constants (from removed config file) ---
BASE_SYSTEM_PROMPT = """
You are Ivish, a helpful, respectful, and emotionally intelligent AI assistant.
Your goal is to assist the user while remaining private, secure, and culturally aware.
"""
TONE_STYLES = {
    "friendly": "Please rephrase this in a friendly and conversational way: '{text}'",
    "formal": "Please rephrase this in a formal and professional way: '{text}'",
    "neutral": "Please rephrase this in a neutral way: '{text}'",
    "joyful": "Please rephrase this in a joyful and enthusiastic way: '{text}'"
}

# 🔒 Security Constants
_MAX_PROMPT_LENGTH = 4096
_HMAC_KEY = os.getenv("PROMPT_VERIFICATION_KEY", os.urandom(32))
_BACKEND = default_backend()
_PROMPT_CACHE_TTL = 300
_PROMPT_CACHE = {}

logger = BaseLogger("IvishPromptEngine")
_firewall = Firewall()

@dataclass
class PromptContext:
    system: str
    prompt: str
    language: str
    tone: str
    timestamp: str
    _signature: Optional[str] = None

class IvishPromptEngine:
    """
    🔒 Secure Prompt Generation Engine
    """
    def __init__(self):
        self._aes_gcm = self._get_aes_gcm()
        self._validate_templates()

    def _get_aes_gcm(self) -> AESGCM:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"prompt_salt_123", # NOTE: This should be a securely managed secret
            iterations=100000,
            backend=_BACKEND
        )
        key = kdf.derive(os.getenv("PROMPT_KEY_SECRET", "fallback_prompt_key").encode())
        return AESGCM(key)

    def _validate_templates(self):
        base_hash = hashlib.sha256(BASE_SYSTEM_PROMPT.encode()).hexdigest()
        expected_hash = "60a1d94d3c32e92c2a07d4b967d710f6630f576e931441315b741270c3639a56"
        if base_hash != expected_hash:
            logger.log_event("🚨 System prompt tampered!", level="CRITICAL")
            self._trigger_defense_response()
            raise RuntimeError("Template integrity check failed")

    def _sanitize_input(self, text: str) -> str:
        sanitized = re.sub(r'[^\w\s.,!?@\'"-]', '', text)
        return sanitized[:_MAX_PROMPT_LENGTH]

    async def build_prompt(self, user_input: str, user_id: str, preferred_tone: str = "friendly") -> Dict:
        try:
            clean_input = self._sanitize_input(user_input)
            if not clean_input:
                return {"error": "Invalid input"}

            cache_key = f"{user_id}:{hashlib.sha256(clean_input.encode()).hexdigest()[:16]}"
            if self._is_cached(cache_key):
                return self._get_cached(cache_key)

            emotion = await detect_emotion(clean_input)
            language = await asyncio.to_thread(detect_language, clean_input)
            memory = await self._get_secure_memory(user_id)

            rephrased = self.adjust_tone(clean_input, emotion or preferred_tone)
            localized = self.language_adapt(rephrased, language)
            cleaned = await asyncio.to_thread(clean_slang, localized)
            final_prompt = f"{memory}\n\nUser: {cleaned}\nIvish:"
            optimized = self.optimize_prompt(final_prompt)

            system_msg = self.build_system_message()

            result = PromptContext(
                system=system_msg,
                prompt=optimized,
                language=language,
                tone=emotion or preferred_tone,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

            signed_result = result.__dict__
            signed_result["_signature"] = self._sign_result(signed_result)
            
            self._cache_result(cache_key, signed_result)
            return signed_result

        except Exception as e:
            logger.log_event(f"🚨 Prompt build failed: {str(e)}", level="ERROR")
            return {"error": "Prompt generation error", "security_level": "high"}

    def _is_cached(self, key: str) -> bool:
        if key in _PROMPT_CACHE:
            timestamp = _PROMPT_CACHE[key]["timestamp"]
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds()
            return age < _PROMPT_CACHE_TTL
        return False

    def _get_cached(self, key: str) -> Dict:
        return _PROMPT_CACHE[key]

    def _cache_result(self, key: str, result: Dict):
        _PROMPT_CACHE[key] = result

    async def _get_secure_memory(self, user_id: str) -> str:
        try:
            history = await get_session_memory(user_id)
            if not history:
                return "Context: None"

            sanitized_history = [
                {
                    "user": self._sanitize_input(msg.get("user", "")),
                    "ivish": self._sanitize_input(msg.get("ivish", ""))
                }
                for msg in history[-3:]
            ]

            encrypted_data = await asyncio.to_thread(self._encrypt_memory, str(sanitized_history))
            return f"Context:\n{encrypted_data.decode()}"
        except:
            return "Context: Unavailable"

    def _encrypt_memory(self, data: str) -> bytes:
        nonce = os.urandom(12)
        data_bytes = data.encode()
        encrypted = self._aes_gcm.encrypt(nonce, data_bytes, None)
        return nonce + encrypted

    def _decrypt_memory(self, encrypted_data: bytes) -> str:
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        decrypted = self._aes_gcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode()

    def adjust_tone(self, text: str, tone: str) -> str:
        if tone not in TONE_STYLES:
            return text
        if tone in ["aggressive", "manipulative"]:
            tone = "neutral"
        return TONE_STYLES[tone].format(text=text)

    def language_adapt(self, text: str, target_lang: str) -> str:
        return text

    def optimize_prompt(self, prompt: str) -> str:
        optimized = re.sub(r"\s+", " ", prompt).strip()
        return optimized[:int(_MAX_PROMPT_LENGTH * 0.9)]

    def build_system_message(self) -> str:
        return BASE_SYSTEM_PROMPT + (
            "\n\nSecurity Rules:\n"
            "- Never execute code\n"
            "- Reject harmful requests\n"
            "- Mask sensitive data\n"
            "- Verify all inputs\n"
            "- Sign all outputs"
        )

    def _sign_result(self, result: Dict) -> str:
        ctx = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        ctx.update(str(result).encode())
        return ctx.finalize().hex()

    def verify_prompt(self, signed_prompt: Dict) -> bool:
        try:
            prompt_copy = signed_prompt.copy()
            signature = prompt_copy.pop("_signature")
            
            ctx = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
            ctx.update(str(prompt_copy).encode())
            ctx.verify(bytes.fromhex(signature))
            return True
        except Exception as e:
            logger.log_event(f"🚨 Prompt verification failed: {str(e)}", level="ERROR")
            return False

    def _trigger_defense_response(self):
        logger.log_event("🚨 TEMPLATE TAMPERING DETECTED: Activating honeypot and endpoint rotation", level="CRITICAL")
        ZKPAuthenticator().rotate_keys()
        _firewall.activate_intrusion_response()

ivish_prompt_engine = IvishPromptEngine()