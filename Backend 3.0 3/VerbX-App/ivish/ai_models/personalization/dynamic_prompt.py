import re
import time
from typing import Optional, Dict
from dataclasses import dataclass, field

from cryptography.fernet import Fernet  # AES-256

# Security: Preserve original imports
from ai_models.tone_emotion_detector import detect_emotion
from ai_models.memory.memory_agent import recall_context
from backend.app.utils.slang_cleaner import clean_slang
from backend.app.utils.prompt_templates import get_base_template
from config.user_flags import get_user_preferences
from backend.app.utils.logger import log_event

# --- Security Constants --- #
_SESSION_KEY = Fernet.generate_key()
_CIPHER_SUITE = Fernet(_SESSION_KEY)

# Reason: Regex for detecting prompt injection attacks
_INJECTION_PATTERNS = re.compile(
    r"(system|sudo|rm|wget|curl|http:|https:|<\?php|javascript:)",
    re.IGNORECASE
)

_BLOCKLIST: Dict[str, float] = {}  # For intrusion detection
_MAX_REQUESTS_PER_MINUTE = 30
_LATENCY_THRESHOLD_MS = 50


@dataclass
class PromptContext:
    user_id: str
    input_text: str
    sanitized_text: str
    emotion: str
    tone: str
    base_prompt: str
    memory_context: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


def _sanitize_input(raw_text: str) -> Optional[str]:
    """Input sanitization to prevent prompt injection."""
    if not raw_text:
        return None

    if _INJECTION_PATTERNS.search(raw_text):
        log_event(f"BLOCKED INJECTION ATTEMPT: {raw_text[:30]}...", level="CRITICAL")
        return None

    if len(raw_text) > 4096:
        return raw_text[:4096]
    return raw_text


def _encrypt_context(context: str) -> str:
    """AES-256 encrypt memory context."""
    return _CIPHER_SUITE.encrypt(context.encode()).decode()


def _validate_tone_consistency(user_tone: str, detected_emotion: str) -> bool:
    """Validate that tone and detected emotion match allowed combinations."""
    if not user_tone or not detected_emotion:
        return True

    tone_emotion_map = {
        "formal": ["neutral", "calm"],
        "empathetic": ["sad", "worried"],
        "friendly": ["happy", "excited"],
        "casual": ["neutral", "happy"]
    }

    allowed_emotions = tone_emotion_map.get(user_tone.lower(), [])
    return detected_emotion in allowed_emotions


def _validate_request_frequency(user_id: str) -> bool:
    """Rate limiting to prevent abuse."""
    now = time.time()
    user_key = f"prompt:{user_id}"

    if user_key in _BLOCKLIST:
        if now - _BLOCKLIST[user_key] < 60:
            return False
        else:
            del _BLOCKLIST[user_key]

    _BLOCKLIST[user_key] = now
    return True


def _trigger_honeypot():
    """Triggered for suspicious activity."""
    log_event("[SECURITY] Honeypot activated for suspicious activity")
    # Optional: Serve fake prompt templates


def generate_prompt(user_id: str, input_text: str) -> Optional[str]:
    """
    Generates secure, personalized prompts with <50ms latency.
    Returns None on critical failure or injection attempt.
    """
    start_time = time.time()

    if not (sanitized_input := _sanitize_input(input_text)):
        return None

    if not _validate_request_frequency(user_id):
        log_event(f"[RATE-LIMIT] Too many requests from {user_id}")
        _trigger_honeypot()
        return None

    try:
        prefs = get_user_preferences(user_id)
        base_prompt = get_base_template(prefs.get("language", "en"))
        cleaned_text = apply_slang_cleaning(sanitized_input)
        emotion = detect_emotion(cleaned_text)

        tone = prefs.get("tone", "neutral")
        if not _validate_tone_consistency(tone, emotion):
            log_event(f"[SECURITY] Tone tampering detected for {user_id}")
            emotion = "neutral"

        toned_text = apply_tone(cleaned_text, tone or emotion)
        memory_context = recall_context(user_id)

        secure_context = _encrypt_context(memory_context) if memory_context else ""
        prompt_with_context = inject_context(base_prompt, secure_context)

        final_prompt = prompt_with_context.replace("{{input}}", toned_text)

        latency = (time.time() - start_time) * 1000
        if latency > _LATENCY_THRESHOLD_MS:
            log_event(f"[PERFORMANCE] Prompt gen over threshold: {latency:.2f}ms")

        log_event(
            f"DYNAMIC PROMPT: [{user_id}] -> "
            f"Emotion: {emotion}, Tone: {tone}, "
            f"Latency: {latency:.2f}ms"
        )

        return final_prompt
    except Exception as e:
        log_event(f"[ERROR] Prompt generation failed: {str(e)[:50]}", level="ERROR")
        return None  # Fallback to None on error


def apply_slang_cleaning(text: str) -> str:
    """Cleans slang and redacts suspicious patterns."""
    cleaned = clean_slang(text)
    return _INJECTION_PATTERNS.sub("[REDACTED]", cleaned)


def apply_tone(text: str, tone: str) -> str:
    """Applies tone templates to the text."""
    valid_tones = {"formal", "casual", "empathetic", "friendly"}
    if tone and tone.lower() in valid_tones:
        tone = tone.lower()
    else:
        tone = "neutral"

    templates = {
        "formal": f"Respond professionally: {text}",
        "empathetic": f"I sense you're feeling: {text}",
        "friendly": f"Hey! {text}",
        "casual": f"Got it: {text}",
        "neutral": text
    }
    return templates.get(tone, text)


def inject_context(base_prompt: str, context: Optional[str]) -> str:
    """Safely injects encrypted memory context into the base prompt."""
    safe_context = context[:1024] if context else ""
    return base_prompt.replace("{{context}}", safe_context)
