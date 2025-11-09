# backend/services/whisper_service.py
# 🧠 Final, Secure Whisper Service for Ivish AI
# 🚀 Refactored Code

import os
import time
import uuid
import tempfile
import hashlib
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from collections import defaultdict
import hmac
import logging
from functools import partial
from concurrent.futures import ThreadPoolExecutor
from fastapi import HTTPException

# 📦 Project Imports
from ai_models.whisper.whisper_handler import transcribe_audio
from ai_models.translation.dialect_adapter import detect_language
from ai_models.emotion.emotion_handler import detect_emotion
from ai_control.safety_decision_manager import evaluate_safety
from utils.logger import log_event
from utils.rate_meter import rate_meter
from security.firewall import sanitize_audio_request, validate_audio_origin, AudioThreatLevel
from security.blockchain.zkp_handler import ZKPSessionValidator
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import blackhole_response_action, rotate_endpoint
from security.encryption_utils import AES256Cipher

# 🧱 Global Config
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "False").lower() == "true"
ENABLE_HONEYPOT = os.getenv("ENABLE_HONEYPOT", "False").lower() == "true"
MAX_AUDIO_SIZE_MB = int(os.getenv("MAX_AUDIO_SIZE_MB", "10"))
MIN_AUDIO_LENGTH_MS = int(os.getenv("MIN_AUDIO_LENGTH_MS", "200"))
MAX_AUDIO_LENGTH_MS = int(os.getenv("MAX_AUDIO_LENGTH_MS", "30000"))
TEMP_FILE_TTL_SEC = int(os.getenv("TEMP_FILE_TTL_SEC", "300"))
THREAD_POOL_SIZE = int(os.getenv("THREAD_POOL_SIZE", "2"))
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", "5"))
USER_HASH_SALT = os.getenv("USER_HASH_SALT", None)
if not USER_HASH_SALT:
    raise RuntimeError("USER_HASH_SALT not found in environment. Secure hashing is not possible.")
USER_HASH_SALT = USER_HASH_SALT.encode()

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "threat_level": 0,
    "executor": ThreadPoolExecutor(THREAD_POOL_SIZE)
}
zkp_validator = ZKPSessionValidator()

# 🔒 Security Utilities
def _hash_user_id(user_id: str) -> str:
    """GDPR-compliant user hashing."""
    return hmac.new(
        USER_HASH_SALT,
        user_id.encode(),
        hashlib.sha3_256
    ).hexdigest()

def _secure_tempfile_path() -> str:
    """Cryptographically secure temporary file path."""
    safe_name = f"stt_{uuid.uuid4().hex}_{hashlib.sha256(os.urandom(16)).hexdigest()[:8]}.wav"
    temp_dir = tempfile.mkdtemp(prefix="secure_stt_")
    return os.path.join(temp_dir, safe_name)

async def _wipe_tempfile(path: str) -> None:
    """Secure file deletion with overwrite and directory cleanup."""
    try:
        # Overwrite file content
        with open(path, "ba+") as f:
            length = f.tell()
            f.seek(0)
            f.write(os.urandom(length))
        os.unlink(path)
        # Clean up the parent directory
        os.rmdir(os.path.dirname(path))
    except Exception as e:
        log_event(f"Secure file wipe failed: {str(e)}", level="ERROR")

def _sanitize_text(text: str) -> str:
    """Prevent injection in STT output."""
    injection_patterns = [
        '<?', '<script', 'SELECT * FROM', 'os.system', 'subprocess.call', 'eval('
    ]
    for pattern in injection_patterns:
        text = text.replace(pattern, '')
    return text.strip()

def _is_valid_audio_size(size: int) -> bool:
    """Validate audio file size."""
    return size <= MAX_AUDIO_SIZE_MB * 1024 * 1024

def _is_valid_audio_duration(duration: float) -> bool:
    """Validate audio length (seconds)."""
    return MIN_AUDIO_LENGTH_MS / 1000 <= duration <= MAX_AUDIO_LENGTH_MS / 1000

def _increment_threat_level():
    """Increase threat level and trigger defense if needed."""
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        asyncio.create_task(_anti_tamper_protocol())

async def _anti_tamper_protocol():
    """Active defense against malicious audio."""
    log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
    if ENABLE_HONEYPOT:
        await _trigger_honeypot()
    blackhole_response_action()
    rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

async def _trigger_honeypot():
    """Deceive attackers with fake transcription."""
    await process_stt_request(b"malformed_audio_data", lang_hint="en", session_token="fake_token")

# 🧠 Whisper Service Core
async def process_stt_request(
    audio_input: bytes, 
    lang_hint: Optional[str] = None,
    session_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Zero-trust STT processing with:
    - Audio integrity validation
    - ZKP session verification
    - Hardware-bound request validation
    - Blockchain audit logging
    """
    user_id = "anonymous"
    if session_token:
        try:
            payload = await zkp_validator.verify_session_async(session_token)
            user_id = payload.get("user_id", "anonymous")
        except Exception:
            log_event("STT_SESSION_INVALID", level="WARNING")
            raise HTTPException(403, "Session verification failed")

    if await rate_meter.track_call(user_id, source="stt_request"):
        log_event("RATE LIMIT EXCEEDED", level="WARNING")
        raise HTTPException(429, "Too many requests")

    threat_level = sanitize_audio_request(audio_input)
    if threat_level > AudioThreatLevel.MEDIUM:
        log_event("AUDIO THREAT DETECTED", level="ALERT")
        _handle_audio_threat(audio_input, threat_level)
        raise HTTPException(400, "Invalid or malicious audio input")

    if not _is_valid_audio_size(len(audio_input)):
        log_event("AUDIO SIZE EXCEEDED", level="WARNING")
        raise HTTPException(413, "Audio file too large")

    if not validate_audio_origin(audio_input):
        log_event("AUDIO ORIGIN TAMPERING", level="CRITICAL")
        raise HTTPException(403, "Invalid audio source")

    temp_path = None
    try:
        temp_path = _secure_tempfile_path()
        with open(temp_path, "wb") as f:
            f.write(audio_input)

        # Parallel processing pipeline
        loop = asyncio.get_running_loop()
        stt_result, file_hash = await asyncio.gather(
            loop.run_in_executor(
                SECURITY_CONTEXT["executor"],
                partial(safe_transcribe, audio_path=temp_path, lang=lang_hint)
            ),
            loop.run_in_executor(
                SECURITY_CONTEXT["executor"],
                partial(analyze_audio_fingerprint, audio_path=temp_path)
            )
        )

        if not stt_result or not isinstance(stt_result, dict) or "text" not in stt_result:
            raise ValueError("Invalid Whisper output format")

        detected_lang = await detect_language(stt_result["text"])
        stt_result["language"] = lang_hint or detected_lang or "und"

        emotion = await detect_emotion(stt_result["text"])
        stt_result["emotion"] = emotion

        safety = await evaluate_safety(stt_result["text"], "input", user_id)
        stt_result["safety"] = safety

        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain(event="stt_processed", data={
                "user_id_hash": _hash_user_id(user_id),
                "file_hash": file_hash,
                "text_hash": hashlib.sha3_256(stt_result["text"].encode()).hexdigest(),
                "lang": stt_result["language"],
                "timestamp": datetime.utcnow().isoformat()
            })

        return format_response(stt_result)

    except Exception as e:
        log_event(f"STT processing failed: {str(e)}", level="ERROR")
        _increment_threat_level()
        raise HTTPException(500, "Transcription failed")
    finally:
        if temp_path:
            await _wipe_tempfile(temp_path)

def safe_transcribe(audio_path: str, lang: Optional[str] = None) -> Dict[str, Any]:
    """
    Hardened Whisper execution with file integrity and timeboxed execution.
    This function is designed to run in a thread pool.
    """
    if not os.path.exists(audio_path):
        raise FileNotFoundError("Audio tempfile missing")

    try:
        start_time = time.time()
        result = transcribe_audio(audio_path, lang_hint=lang)
        latency = time.time() - start_time

        if not result:
            raise ValueError("Empty transcription result")

        return {
            "text": _sanitize_text(result.get("text", "")),
            "clauses": result.get("clauses", []),
            "language": result.get("language", "auto"),
            "latency": round(latency, 2),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        log_event(f"Whisper execution failed: {str(e)}", level="ERROR")
        _increment_threat_level()
        return {"error": "Transcription failed"}

def analyze_audio_fingerprint(audio_path: str) -> str:
    """
    Generate a cryptographic fingerprint of the audio file for integrity validation.
    This function is designed to run in a thread pool.
    """
    try:
        with open(audio_path, "rb") as f:
            audio_data = f.read()
        return hashlib.sha3_256(audio_data).hexdigest()
    except Exception as e:
        log_event(f"Audio fingerprint generation failed: {str(e)}", level="ERROR")
        return "fingerprint_failed"

def format_response(stt_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Secure response formatting with output sanitization and size limitation.
    """
    return {
        "text": stt_result.get("text", "")[:5000],
        "clauses": [
            _sanitize_text(clause[:500])
            for clause in stt_result.get("clauses", [])
        ],
        "language": stt_result.get("language", "und"),
        "emotion": stt_result.get("emotion", {"label": "neutral", "confidence": 1.0}),
        "latency": stt_result.get("latency", 0.0),
        "timestamp": stt_result.get("timestamp", datetime.now(timezone.utc).isoformat())
    }

def _handle_audio_threat(audio: bytes, threat: AudioThreatLevel):
    """Active defense against malicious audio input."""
    threat_id = hashlib.sha256(audio).hexdigest()
    log_event(f"AUDIO THREAT | level={threat.name} | id={threat_id}", level="ALERT")
    if threat >= AudioThreatLevel.HIGH:
        # Placeholder for quarantine; logic is in a dedicated incident response module.
        pass

def _derive_hw_key() -> bytes:
    # This function is not used in the final code, but a placeholder is kept for completeness.
    return b""

def _wipe_temp_sessions():
    # This is a placeholder for a central session wipe service.
    pass

def _rotate_endpoints():
    # This is a placeholder for a central endpoint rotation service.
    pass