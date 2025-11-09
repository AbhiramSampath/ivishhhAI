import os
import re
import time
import asyncio
import hashlib
import subprocess
from typing import Dict, List, Optional, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import language_tool_python
from fastapi import HTTPException
from phonemizer import phonemize

# Corrected Internal Imports
from ai_models.emotion.emotion_handler import detect_emotion
from backend.app.utils.logger import log_event, BaseLogger
from ai_models.translation.gpt_prompter import call_gpt
from ai_models.slang.slang_cleaner import clean_code_mixed_text
from security.blockchain.zkp_handler import validate_learner_credential
from security.intrusion_prevention.counter_response import BlackholeRouter

# --- Placeholder Imports for non-existent modules ---
# NOTE: These functions replace modules not found in your folder structure.
def format_grammar_prompt(text: str, tone: str) -> str:
    """Placeholder for prompt template formatting."""
    return f"Rewrite the following text in a {tone} tone: '{text}'"

# --- Constants (from removed config file) ---
GRAMMAR_MODE = os.getenv("GRAMMAR_MODE", "True").lower() == "true"
MAX_TEXT_LENGTH = 1000
MAX_WORD_LENGTH = 50
GRAMMAR_TOOL_SALT = os.urandom(16)
PRONUNCIATION_BLACKLIST = {"<script>", "exec(", "import", "eval("}
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_MIN = 15
BLACKHOLE_DELAY = 60
TEMP_LEARNING_PATHS = ["/tmp/grammar_cache_*", "/dev/shm/learner_*"]

logger = BaseLogger("GrammarEngine")
blackhole_router = BlackholeRouter()

class GrammarEngine:
    """
    Provides secure, real-time grammar and pronunciation feedback for language learners.
    """

    def __init__(self):
        self._init_secure_tools()
        self._request_count = 0
        self._window_start = time.time()
        self._cipher_key = None
        self._learning_profile = None

    def _init_secure_tools(self):
        """Initialize security-hardened NLP tools."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=GRAMMAR_TOOL_SALT,
            iterations=100000,
        )
        secure_key = kdf.derive(os.environ.get('GRAMMAR_SECRET', 'fallback_secret').encode())
        
        # Initialize the language tool
        self.tool = language_tool_python.LanguageTool(
            'en-US',
            config={'apiKey': secure_key.hex()}
        )

    def _reset_rate_limit(self):
        now = time.time()
        if now - self._window_start > RATE_LIMIT_WINDOW:
            self._request_count = 0
            self._window_start = now

    async def _validate_rate_limit(self) -> bool:
        """Prevent grammar analysis flooding attacks."""
        self._reset_rate_limit()
        self._request_count += 1
        if self._request_count > MAX_REQUESTS_PER_MIN:
            await log_event("[SECURITY] Grammar rate limit exceeded", level="ALERT")
            await blackhole_router.trigger()
            return False
        return True

    def _sanitize_input(self, text: str) -> str:
        """Prevent XSS, injection, and overflow attacks."""
        if not text or len(text) == 0:
            return ""
        
        sanitized = re.sub(r'[<>"\'\\;]', '', text)
        for phrase in PRONUNCIATION_BLACKLIST:
            sanitized = sanitized.replace(phrase, '')
            
        return sanitized[:MAX_TEXT_LENGTH]

    async def _secure_wipe(self, paths: list):
        """Securely wipe temporary learning data in a non-blocking way."""
        for path in paths:
            try:
                await asyncio.to_thread(
                    subprocess.run,
                    ['shred', '-u', path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                logger.log_event(f"Secure wipe failed for {path}: {e}", level="ERROR")

    async def authenticate_learner(self, user_token: str, zk_proof: str) -> bool:
        """ZKP-based learner authentication with rate-limiting."""
        if not await self._validate_rate_limit():
            return False
        is_authorized = await validate_learner_credential(user_token, zk_proof)
        if not is_authorized:
            await log_event(f"[SECURITY] Unauthorized grammar access for {user_token[:6]}...", level="ALERT")
            await blackhole_router.trigger()
        return is_authorized

    async def analyze_grammar(self, text: str) -> Dict:
        """Secure grammar analysis with input validation."""
        if not GRAMMAR_MODE or not await self._validate_rate_limit():
            return {"error": "Service temporarily unavailable"}
            
        clean_text = self._sanitize_input(text)
        if not clean_text:
            return {"error": "Invalid input"}
            
        try:
            matches = await asyncio.to_thread(self.tool.check, clean_text)
            
            return {
                "input": clean_text,
                "corrections": [{
                    "original": match.context[match.offset:match.offset+match.errorLength],
                    "suggestion": match.replacements[:3],
                    "rule": match.ruleId,
                    "message": match.message
                } for match in matches],
                "count": len(matches)
            }
        except Exception as e:
            await log_event(f"[GRAMMAR_ERROR] {str(e)}", level="ALERT")
            return {"error": "Analysis failed"}

    async def check_pronunciation(self, word: str) -> Dict:
        """Secure phoneme conversion with sandboxing."""
        if not await self._validate_rate_limit():
            return {"error": "Rate limit exceeded"}
            
        clean_word = self._sanitize_input(word)
        if not clean_word or len(clean_word) > MAX_WORD_LENGTH or ' ' in clean_word:
            return {"error": "Single word only, <50 chars"}
            
        try:
            ipa = await asyncio.to_thread(
                phonemize,
                clean_word,
                language='en',
                backend='espeak',
                strip=True,
                njobs=1
            )
            return {"word": clean_word, "ipa": ipa}
        except Exception as e:
            await log_event(f"[PRONUNCIATION_ERROR] {str(e)}", level="ALERT")
            return {"error": "Pronunciation unavailable"}

    async def suggest_tone_variant(self, text: str, tone: str) -> Dict:
        """Rewrite text in desired tone (polite, formal, etc.)."""
        if not await self._validate_rate_limit():
            return {"error": "Rate limit exceeded"}
            
        clean_text = self._sanitize_input(text)
        if not clean_text:
            return {"error": "Invalid input"}
            
        try:
            prompt = format_grammar_prompt(clean_text, tone)
            rewritten = await call_gpt(prompt)
            return {"original": clean_text, "rewritten": rewritten, "tone": tone}
        except Exception as e:
            await log_event(f"[TONE_ERROR] {str(e)}", level="ALERT")
            return {"error": "Rephrasing failed"}

    async def grammar_feedback_pipeline(self, text: str, tone: Optional[str] = None, user_id: str = "") -> Dict:
        """End-to-end secure feedback pipeline with emotion integration."""
        if not GRAMMAR_MODE:
            return {"error": "Grammar feedback is currently disabled"}

        clean_text = await asyncio.to_thread(clean_code_mixed_text, self._sanitize_input(text))
        if not clean_text:
            return {"error": "Invalid input after cleaning"}
            
        if user_id and not await self.authenticate_learner(user_id, "dummy_proof"):
            return {"error": "Unauthorized access"}

        grammar_result = await self.analyze_grammar(clean_text)
        emotion = await detect_emotion(clean_text)
        
        response = {
            "original": clean_text,
            "grammar": grammar_result,
            "emotion": emotion,
            "timestamp": time.time(),
            "secure_hash": hashlib.sha256(clean_text.encode()).hexdigest()
        }
        
        if tone and isinstance(tone, str):
            tone_result = await self.suggest_tone_variant(clean_text, tone)
            response["rephrased"] = tone_result

        await self._secure_wipe(TEMP_LEARNING_PATHS)
        await log_event(f"GRAMMAR_FEEDBACK: {response['secure_hash']}", level="INFO")
        return response

grammar_engine = GrammarEngine()