import os
import re
import time
import asyncio
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from functools import lru_cache

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- Placeholder Imports for non-existent modules ---
def detect_emotion(text: str) -> str:
    """Placeholder for emotion detection."""
    return "neutral"

def get_prompt_template(name: str) -> str:
    """Placeholder for getting a prompt template."""
    return "{text}"

def clean_slang(text: str) -> str:
    """Placeholder for slang cleaning."""
    return text

def gpt_api_call(prompt: str) -> str:
    """Placeholder for a GPT API call."""
    return f"[API Response for: {prompt}]"

def local_model_call(prompt: str) -> str:
    """Placeholder for a local model call."""
    return f"[Local Model Response for: {prompt}]"

class BlackholeRouter:
    """Placeholder for a blackhole router."""
    def trigger(self):
        pass

# Corrected Imports based on project architecture
from backend.app.utils.logger import log_event, BaseLogger

# --- Security Constants --- #
_MAX_INPUT_LENGTH = 1024
_EPHEMERAL_KEY = Fernet.generate_key()
_CIPHER_SUITE = Fernet(_EPHEMERAL_KEY)
_INJECTION_PATTERNS = re.compile(
    r"(system|sudo|rm|wget|curl|http:|https:|<\?php|javascript:|\.exec\()", 
    re.IGNORECASE
)
_TONE_MAPPING = {
    "angry": "polite", "confused": "simplified", "sad": "friendly",
    "happy": "assertive", "neutral": "formal"
}
_BLOCKLIST: Dict[str, float] = {}
_RATE_LIMIT_WINDOW = 60
_MAX_REQUESTS_PER_MINUTE = 30
USE_LOCAL_GPT = os.getenv("USE_LOCAL_GPT", "False").lower() == "true"

logger = BaseLogger("RephraseEngine")

@dataclass
class RephraseContext:
    user_id: Optional[str]
    input_text: str
    sanitized_text: str
    detected_tone: str
    mode: str
    prompt: str
    timestamp: float = field(default_factory=time.time)

def _sanitize_input(raw_text: str) -> Optional[str]:
    if not raw_text:
        return None
    
    if _INJECTION_PATTERNS.search(raw_text):
        log_event("BLOCKED PROMPT INJECTION", level="ALERT")
        return None
    
    sanitized = raw_text[:_MAX_INPUT_LENGTH]
    return sanitized

def _encrypt_prompt(prompt: str) -> bytes:
    return _CIPHER_SUITE.encrypt(prompt.encode())

def _decrypt_prompt(encrypted_prompt: bytes) -> str:
    return _CIPHER_SUITE.decrypt(encrypted_prompt).decode()

def _is_rate_limited(user_id: str) -> bool:
    now = time.time()
    key = f"rephrase:{user_id}"
    
    if key in _BLOCKLIST:
        if now - _BLOCKLIST[key] < _RATE_LIMIT_WINDOW / _MAX_REQUESTS_PER_MINUTE:
            return True
    _BLOCKLIST[key] = now
    return False

def _trigger_honeypot():
    log_event("[SECURITY] Honeypot activated for suspicious activity", level="ALERT")

def _validate_tone_consistency(user_tone: str, detected_emotion: str) -> bool:
    if not user_tone or not detected_emotion:
        return True
    
    tone_emotion_map = {
        "formal": ["neutral", "calm"], "empathetic": ["sad", "worried"],
        "friendly": ["happy", "excited"], "casual": ["neutral", "happy"]
    }
    
    allowed_emotions = tone_emotion_map.get(user_tone.lower(), [])
    return detected_emotion in allowed_emotions

@lru_cache(maxsize=128)
def _cached_emotion_detect(text: str) -> str:
    return detect_emotion(text)

async def rephrase_text(text: str, mode: str = "polite", user_id: Optional[str] = None) -> str:
    start_time = time.time()

    if _is_rate_limited(user_id):
        await log_event(f"[RATE-LIMIT] Too many requests from {user_id}", level="WARNING")
        _trigger_honeypot()
        return "[RATE LIMIT EXCEEDED]"
    
    sanitized_text = _sanitize_input(text)
    if not sanitized_text:
        return "[CONTENT BLOCKED]"
    
    try:
        cleaned_text = await asyncio.to_thread(clean_slang, sanitized_text)
        detected_tone = await asyncio.to_thread(_cached_emotion_detect, cleaned_text)
        
        if mode == "auto":
            mode = _TONE_MAPPING.get(detected_tone, "formal")
        
        if mode not in _TONE_MAPPING.values() and mode != "formal":
            mode = "formal"
        
        prompt = get_prompt_template("rephrase").format(text=cleaned_text, tone=detected_tone, mode=mode)
        encrypted_prompt = await asyncio.to_thread(_encrypt_prompt, prompt)
        
        response = await _secure_llm_call(encrypted_prompt)
        
        if not _validate_output(response):
            await log_event("[SECURITY] LLM output failed validation", level="WARNING")
            raise ValueError("Unsafe output detected")
        
        latency = (time.time() - start_time) * 1000
        if latency > 200:
            await log_event(f"[PERFORMANCE] Rephrase over threshold: {latency:.2f}ms", level="WARNING")
        
        await log_event(
            f"REPHRASE_SUCCESS: mode={mode}, tone={detected_tone}, "
            f"latency={latency:.2f}ms"
        )
        return response
    except Exception as e:
        await log_event(f"REPHRASE_FAILURE: {str(e)[:50]}", level="ERROR")
        fallback_text = cleaned_text if cleaned_text is not None else text
        detected_tone = detected_tone if detected_tone is not None else mode
        return _fallback_rephrase(fallback_text, detected_tone)

async def _build_prompt(text: str, tone: str, mode: str) -> str:
    template = await asyncio.to_thread(get_prompt_template, "rephrase")
    return template.format(text=text, tone=tone, mode=mode)

async def _secure_llm_call(encrypted_prompt: bytes) -> str:
    try:
        prompt = await asyncio.to_thread(_decrypt_prompt, encrypted_prompt)
        
        if USE_LOCAL_GPT:
            return await local_model_call(prompt)
        return await gpt_api_call(prompt)
    except Exception as e:
        await log_event(f"LLM_FAILURE: {str(e)[:50]}", level="ERROR")
        raise

def _validate_output(text: str) -> bool:
    if not text or _INJECTION_PATTERNS.search(text):
        return False
    if len(text) > _MAX_INPUT_LENGTH * 2:
        return False
    return True

def _fallback_rephrase(text: str, tone: str) -> str:
    fallbacks = {
        "polite": f"Could you please clarify: '{text}'?",
        "friendly": f"I'd love to help! What do you mean by '{text}'?",
        "formal": f"Requesting clarification regarding: '{text}'",
        "simplified": f"What is your question about '{text}'?",
        "assertive": f"I can help with '{text}'. What do you need?",
    }
    return fallbacks.get(tone, f"Requesting clarification regarding: '{text}'")

def _exceeds_rate_limit(user_id: str) -> bool:
    return False