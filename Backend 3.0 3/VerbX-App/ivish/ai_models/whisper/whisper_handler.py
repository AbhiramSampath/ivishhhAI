import time
import asyncio
import hashlib
import unicodedata
import re
import os
import threading
from typing import AsyncGenerator, Dict, List, Optional, Any
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# --- Placeholder Imports for non-existent modules ---
WHISPER_MODE = os.getenv("WHISPER_MODE", "offline")
SUPPORTED_LANGUAGES = ["en", "hi", "ta", "te", "bn"]

def preprocess_audio(audio_data: bytes, stream: bool = False) -> Any:
    """Placeholder for audio preprocessor."""
    return audio_data

def detect_language(text: str) -> str:
    """Placeholder for language detection."""
    return "en"

def transcribe_offline(audio_data: Any, lang: str) -> Dict[str, str]:
    """Placeholder for offline transcription."""
    return {"text": "offline transcription"}

def transcribe_api(audio_data: Any, lang: str) -> Dict[str, str]:
    """Placeholder for API transcription."""
    return {"text": "api transcription"}

def validate_session_token(user_id: Optional[str]) -> bool:
    """Placeholder for session token validation."""
    return True

def has_user_consented(user_id: Optional[str], scope: str) -> bool:
    """Placeholder for user consent validation."""
    return True

# Corrected Internal imports
from backend.app.utils.logger import log_event, BaseLogger

# Security constants
MAX_AUDIO_LENGTH = 30
ANTI_DOS_DELAY = 0.01
BLACKLISTED_PHRASES = {
    hashlib.sha256(b'malicious_phrase1').hexdigest(),
    hashlib.sha2-56(b'malicious_phrase2').hexdigest()
}
SLA_LATENCY_THRESHOLD = 0.2

_AUDIO_HMAC_KEY = None
_AUDIO_HMAC_KEY_HOUR = None
_AUDIO_HMAC_KEY_LOCK = threading.Lock()
_whisper_killed = False

logger = BaseLogger("WhisperHandler")

def get_audio_hmac_key() -> bytes:
    global _AUDIO_HMAC_KEY, _AUDIO_HMAC_KEY_HOUR
    with _AUDIO_HMAC_KEY_LOCK:
        current_hour = int(time.time() // 3600)
        if _AUDIO_HMAC_KEY is None or _AUDIO_HMAC_KEY_HOUR != current_hour:
            _AUDIO_HMAC_KEY = os.urandom(32)
            _AUDIO_HMAC_KEY_HOUR = current_hour
        return _AUDIO_HMAC_KEY

def _validate_audio(audio_data: bytes) -> bool:
    if _whisper_killed:
        return False
    
    if len(audio_data) > MAX_AUDIO_LENGTH * 16000 * 2:
        log_event("[SECURITY] Oversized audio input", level="WARNING")
        return False
    
    try:
        h = hmac.HMAC(get_audio_hmac_key(), hashes.SHA256(), backend=default_backend())
        h.update(audio_data)
        audio_hash = h.finalize().hex()
        if audio_hash in BLACKLISTED_PHRASES:
            log_event(f"[SECURITY] Blacklisted audio detected: {audio_hash}", level="CRITICAL")
            return False
    except Exception as e:
        log_event(f"[SECURITY] HMAC validation failed: {str(e)[:50]}", level="ERROR")
        return False
    
    return True

def _sanitize_text(text: str) -> str:
    if not text or _whisper_killed:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    text_hash = hashlib.sha256(text.encode()).hexdigest()
    if text_hash in BLACKLISTED_PHRASES:
        return ""
    return text.strip()

def _log_transcription_event(text: str, lang: str, latency: float, user_id: Optional[str] = None):
    try:
        meta = {"language": lang, "latency": f"{latency:.3f}s", "input_hash": hashlib.sha256(text.encode()).hexdigest()}
        if user_id:
            meta["user_id"] = user_id[:6] + "..."
        log_event("Whisper transcription performed", level="INFO", meta=meta, sanitize=True)
    except Exception as e:
        pass

def get_engine():
    if _whisper_killed:
        raise RuntimeError("Whisper engine killed")
    try:
        if WHISPER_MODE == "offline":
            return transcribe_offline
        return transcribe_api
    except Exception as e:
        log_event(f"[SECURITY] Engine init failed: {str(e)}", level="CRITICAL")
        raise RuntimeError("STT engine unavailable")

def buffer_clauses(text: str, max_len: int = 12) -> List[str]:
    if _whisper_killed:
        return []
    text = _sanitize_text(text)
    if not text:
        return []
    sentences = re.split(r'[.?!]', text)
    clauses = []
    for sent in sentences:
        words = sent.strip().split()
        for i in range(0, len(words), max_len):
            clause = " ".join(words[i:i+max_len])
            if clause:
                clauses.append(clause)
        if len(clauses) > 50:
            break
    return clauses

async def transcribe_audio(audio_path: str, lang_hint: str = None, user_id: Optional[str] = None) -> Dict:
    if _whisper_killed or not validate_session_token(user_id):
        return {"text": "", "clauses": [], "language": "en", "latency": 0}
    start = time.perf_counter()
    try:
        with open(audio_path, 'rb') as f:
            audio_data = f.read()
        if not _validate_audio(audio_data):
            return {"text": "", "clauses": [], "language": "en", "latency": 0}
        lang_hint = lang_hint or await asyncio.to_thread(detect_language, audio_data[:16000])
        lang_hint = lang_hint if lang_hint in SUPPORTED_LANGUAGES else "en"
        engine = get_engine()
        result = await asyncio.to_thread(engine, preprocess_audio(audio_data), lang=lang_hint)
        text = _sanitize_text(result.get("text", ""))
        clauses = buffer_clauses(text)
        latency = time.perf_counter() - start
        if latency > SLA_LATENCY_THRESHOLD:
            log_event(f"[PERF] STT latency exceeded: {latency:.3f}s", level="WARNING")
        _log_transcription_event(text, lang_hint, latency, user_id)
        return {"text": text, "clauses": clauses, "language": lang_hint, "latency": latency, "engine": WHISPER_MODE}
    except Exception as e:
        log_event(f"[SECURITY] Transcription failed: {str(e)}", level="ERROR")
        return {"text": "", "clauses": [], "language": "en", "latency": 0}

async def stream_transcribe(mic_stream, lang_hint: str = None, user_id: Optional[str] = None) -> AsyncGenerator[Dict, None]:
    if _whisper_killed or not validate_session_token(user_id):
        return
    engine = get_engine()
    chunk_count = 0
    while True:
        try:
            chunk = await mic_stream.read()
            if not chunk or not _validate_audio(chunk):
                break
            chunk_count += 1
            if chunk_count > 100:
                log_event("[SECURITY] Stream chunk limit exceeded", level="WARNING")
                break
            audio = preprocess_audio(chunk, stream=True)
            lang_hint = lang_hint or await asyncio.to_thread(detect_language, audio[:16000])
            lang_hint = lang_hint if lang_hint in SUPPORTED_LANGUAGES else "en"
            result = await asyncio.to_thread(engine, audio, lang=lang_hint)
            text = _sanitize_text(result.get("text", ""))
            yield {"clauses": buffer_clauses(text), "language": lang_hint, "raw": text}
            await asyncio.sleep(ANTI_DOS_DELAY)
        except Exception as e:
            log_event(f"[SECURITY] Stream transcription failed: {str(e)}", level="ERROR")
            break

def kill_whisper():
    global _whisper_killed, _AUDIO_HMAC_KEY, _AUDIO_HMAC_KEY_HOUR
    _whisper_killed = True
    if _AUDIO_HMAC_KEY is not None:
        try:
            overwrite = bytearray(len(_AUDIO_HMAC_KEY))
            for i in range(len(_AUDIO_HMAC_KEY)):
                overwrite[i] = 0
            _AUDIO_HMAC_KEY = bytes(overwrite)
        except Exception:
            pass
    _AUDIO_HMAC_KEY = None
    _AUDIO_HMAC_KEY_HOUR = None
    log_event("Whisper: Engine killed.", level="CRITICAL")

def revive_whisper():
    global _whisper_killed
    _whisper_killed = False
    log_event("Whisper: Engine revived.", level="INFO")

def is_whisper_alive() -> bool:
    return not _whisper_killed

__all__ = ["transcribe_audio", "stream_transcribe", "kill_whisper", "revive_whisper", "is_whisper_alive", "buffer_clauses"]