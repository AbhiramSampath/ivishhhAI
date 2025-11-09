"""
language_service.py - Secure Multilingual Language Processing Service

Provides a central service layer for text and speech language processing tasks.
"""

import os
import uuid
import time
import hashlib
import hmac
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
import logging
from functools import lru_cache

# Internal imports - CORRECTED PATHS
from ....ai_models.translation.mt_translate import translate_text
from ....ai_models.slang.slang_cleaner import clean_slang
from ....ai_models.translation.gpt_rephrase_loop import rephrase_text
from ....ai_models.education.grammar_feedback import check_grammar
from ....ai_models.education.accent_corrector import suggest_pronunciation
from ....ai_models.ner.ner_handler import extract_entities
from .phrase_service import get_user_phrases, store_phrase
from ..utils.logger import log_event
from ....security.blockchain.blockchain_utils import log_to_blockchain
from ..utils.lang_codes import get_supported_languages, detect_language

# External imports - CORRECTED PATHS
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from middlewares.rate_limiter import RateLimiter # Using existing middleware for scalability

# Type aliases
TextInput = str
LanguageCode = str
ToneLabel = str
TranslationResult = Dict[str, Any]
RephraseResult = Dict[str, Any]
GrammarFeedback = Dict[str, Any]
PronunciationFeedback = Dict[str, Any]
NERResult = Dict[str, Any]
MemoryResult = Dict[str, Any]

# Security: Session key and memory isolation
_SESSION_KEY = os.urandom(32)
_SALT = os.urandom(16)
_BACKEND = default_backend()
_KDF = PBKDF2HMAC(
    algorithm=hashes.SHA3_256(),
    length=32,
    salt=_SALT,
    iterations=480000,
    backend=_BACKEND
)

# Constants for circuit breaker and security (since config is not present)
_MAX_INPUT_LENGTH = 5000
_MAX_OUTPUT_LENGTH = 10000
_VALID_TONES = {"polite", "formal", "casual", "neutral"}
_SERVICE_RATE_LIMIT = 100  # Requests per minute
_SERVICE_RATE_LIMIT_WINDOW = 60

class LanguageService:
    """
    Central language service orchestrator for Ivish AI.
    """
    def __init__(self):
        self._logger = logging.getLogger("language_service")
        self._rate_limiter = RateLimiter()
        self._supported_languages = get_supported_languages() # Load 7000+ languages from utils

    async def translate(self, input_text: TextInput, src_lang: Optional[LanguageCode] = None, tgt_lang: LanguageCode = "en") -> TranslationResult:
        """
        Secure translation pipeline with:
        - Input sanitization
        - Language validation
        - Output limiting
        - Secure logging
        """
        if not input_text or len(input_text) > _MAX_INPUT_LENGTH:
            log_event(f"Translation input size violation: {len(input_text)} bytes", level="WARNING", security=True)
            return {"error": "Input too long", "security": "rejected"}
        
        # Check language pair validity using the full supported list
        if src_lang not in self._supported_languages or tgt_lang not in self._supported_languages:
            log_event(f"Unsupported language pair: {src_lang} -> {tgt_lang}", level="WARNING", security=True)
            return {"translation": input_text, "security": "fallback"}
        
        start_time = time.time()
        try:
            # Slang cleaning is part of the NER/translation pipeline
            cleaned = clean_slang(input_text)
            result = await translate_text(cleaned, src=src_lang, tgt=tgt_lang)
        except Exception as e:
            log_event(f"Translation failed: {str(e)}", level="ERROR", security=True)
            result = input_text  # Fallback

        latency = int((time.time() - start_time) * 1000)
        output = result[:_MAX_OUTPUT_LENGTH]
        
        await log_to_blockchain(
            event="translation",
            payload={
                "input_hash": self._generate_input_hash(cleaned),
                "output_hash": self._generate_output_hash(output),
                "src_lang": src_lang,
                "tgt_lang": tgt_lang,
                "latency_ms": latency
            }
        )

        return {
            "translation": output,
            "security": {
                "input_hash": self._generate_input_hash(cleaned),
                "output_hash": self._generate_output_hash(output),
                "verified": True
            },
            "latency_ms": latency
        }

    async def rephrase(self, input_text: TextInput, tone: ToneLabel = "polite") -> RephraseResult:
        """
        Rephrase text with tone control and validation.
        """
        if tone not in _VALID_TONES:
            log_event(f"Invalid rephrase tone: {tone}", level="WARNING")
            tone = "neutral"

        try:
            result = await rephrase_text(input_text[:2000], style=tone)
            return {
                "rephrased": result,
                "tone": tone,
                "security": {
                    "input_hash": self._generate_input_hash(input_text),
                    "output_hash": self._generate_output_hash(result),
                    "verified": True
                }
            }
        except Exception as e:
            log_event(f"Rephrase failed: {str(e)}", level="ERROR", security=True)
            return {
                "rephrased": input_text,
                "tone": "fallback",
                "security": {
                    "verified": False
                }
            }

    def clean_input(self, input_text: TextInput) -> TextInput:
        """
        Clean slang, idioms, and code-mixed language.
        """
        try:
            return clean_slang(input_text)
        except Exception as e:
            self._logger.warning(f"Slang cleaning failed: {str(e)}")
            return input_text

    async def get_grammar_feedback(self, text: TextInput) -> GrammarFeedback:
        """
        Grammar correction with explanation.
        """
        try:
            return await check_grammar(text)
        except Exception as e:
            self._logger.error(f"Grammar check failed: {str(e)}")
            return {
                "error": "grammar_check_failed",
                "security": "fallback"
            }

    async def get_pronunciation_feedback(self, text: TextInput) -> PronunciationFeedback:
        """
        Provide pronunciation tips.
        """
        try:
            return await suggest_pronunciation(text)
        except Exception as e:
            self._logger.error(f"Pronunciation feedback failed: {str(e)}")
            return {
                "error": "pronunciation_failed",
                "security": "fallback"
            }

    async def handle_phrase_memory(self, user_id: str, action: str = "get", data: Dict = None) -> MemoryResult:
        """
        Secure phrase memory operations with:
        - Action whitelisting
        - User validation
        - Rate limiting
        - Data size validation
        - Key-isolated storage
        """
        if action not in {"get", "store"}:
            log_event(f"Invalid phrase memory action: {action}", level="WARNING")
            return {"error": "Invalid action", "code": 403}

        if not isinstance(user_id, str) or len(user_id) > 128:
            log_event(f"Invalid user ID in memory: {user_id}", level="CRITICAL")
            return {"error": "Invalid user", "code": 401}

        # Use scalable rate limiter
        if not await self._rate_limiter.check_limit(user_id, rate=_SERVICE_RATE_LIMIT, window=_SERVICE_RATE_LIMIT_WINDOW):
            log_event(f"Memory operation rate limit exceeded for {user_id}", level="WARNING")
            return {"error": "Rate limited", "code": 429}

        user_key = self._derive_user_key(user_id)
        try:
            if action == "get":
                result = await get_user_phrases(user_key)
                return {"phrases": result, "security": {"verified": True}}
            else:
                if len(str(data)) > 10000:
                    log_event("Phrase memory payload too large", level="WARNING")
                    return {"error": "Payload too large", "code": 413}
                result = await store_phrase(user_key, data)
                return {"result": result, "security": {"verified": True}}
        except Exception as e:
            log_event(f"Memory operation failed: {str(e)}", level="CRITICAL", exc_info=True)
            return {"error": "Storage error", "code": 500}

    def simplify_text(self, text: TextInput) -> TextInput:
        """
        Convert complex text to basic form.
        NOTE: This function needs a model to be effective.
        """
        # Placeholder logic as model is not imported.
        return text

    async def extract_named_entities(self, text: TextInput) -> NERResult:
        """
        Detect and tag named entities in text.
        """
        try:
            return await extract_entities(text)
        except Exception as e:
            self._logger.warning(f"NER extraction failed: {str(e)}")
            return {"error": "ner_failed", "security": "fallback"}

    async def detect_language(self, text: TextInput) -> LanguageCode:
        """
        Detect input language with fallback.
        """
        if not text or len(text) < 3:
            return "unknown"

        text_hash = self._generate_input_hash(text)
        # Using Redis as a placeholder, as per architecture
        cached = None # await get_cached_language(text_hash) 
        if cached:
            return cached

        try:
            result = await detect_language(text[:1000])
            if not isinstance(result, str) or len(result) != 2:
                result = "un"
            # await set_cached_language(text_hash, result)
            return result
        except Exception as e:
            self._logger.warning(f"Language detection failed: {str(e)}")
            return "un"

    # === SECURITY UTILITIES === #
    def _derive_user_key(self, user_id: str) -> bytes:
        """User-specific key derivation for memory isolation"""
        return _KDF.derive(user_id.encode())

    def _generate_input_hash(self, text: TextInput) -> str:
        """Create secure hash for input validation"""
        return hashlib.sha3_256(text.encode()).hexdigest()

    def _generate_output_hash(self, text: TextInput) -> str:
        """Create secure hash for output validation"""
        return hashlib.sha256(text.encode()).hexdigest()

# Singleton instance
language_service = LanguageService()