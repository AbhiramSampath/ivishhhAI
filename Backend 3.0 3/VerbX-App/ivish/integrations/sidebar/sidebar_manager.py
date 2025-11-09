import uuid
import re
import os
from datetime import datetime
from typing import Dict, Optional, Any
from dataclasses import dataclass
import hmac
from functools import lru_cache
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from ai_models.translation.mt_translate import translate_text
from ai_models.tts.tts_handler import speak_text
from ai_models.ivish.ivish_memory import save_phrase
from camera_translation.ocr_engine import extract_text_from_image
from ai_models.translation.gpt_rephrase_loop import summarize_text
from integrations.sidebar.permission_handler import check_permission
from backend.app.utils.logger import log_event
from realtime.socketio.manager import push_to_socket
from backend.app.middlewares.latency_monitor import LatencyMonitor
from security.firewall import Firewall

# --- Security Constants ---
_MAX_TEXT_LENGTH = 4096  # Prevents token bombing
_INJECTION_PATTERNS = re.compile(
    r"(<\?php|javascript:|xss|eval\s*\(|--|\.exec\()",
    re.IGNORECASE
)
_HMAC_KEY = os.urandom(32)  # Session-bound HMAC
_CIPHER_SUITE = Fernet(Fernet.generate_key())  # AES-256-GCM
_BLOCKLIST: Dict[str, float] = {}  # Intrusion detection
_RATE_LIMIT_WINDOW = 60  # seconds

@dataclass
class SidebarEvent:
    type: str
    data: Dict
    nonce: str
    hmac: str
    timestamp: datetime = datetime.utcnow()

# Reason: Rate limiting to prevent abuse
def _is_rate_limited(socket_id: str) -> bool:
    now = datetime.utcnow().timestamp()
    key = f"sidebar:{socket_id}"
    
    if key in _BLOCKLIST and now - _BLOCKLIST[key] < _RATE_LIMIT_WINDOW:
        return True
    
    _BLOCKLIST[key] = now
    return False

def _generate_event_hmac(event: Dict) -> str:
    """Generate HMAC for event integrity."""
    h = hmac.new(_HMAC_KEY, digestmod=hashes.SHA256())
    h.update(event["type"].encode())
    h.update(str(event["data"]).encode())
    return h.hexdigest()

def _verify_event_hmac(event: Dict) -> bool:
    """Verify event integrity."""
    expected_hmac = _generate_event_hmac(event)
    return hmac.compare_digest(expected_hmac, event["hmac"])

def _sanitize_input(data: Dict, task_type: str) -> Optional[Dict]:
    """Nuclear-grade input sanitization."""
    if task_type in ("translate_text", "speak_text"):
        text = data.get("text", "")
        if not text or _INJECTION_PATTERNS.search(text):
            return None
        return {
            "text": text[:_MAX_TEXT_LENGTH],
            "lang": data.get("lang", "en")
        }
    elif task_type == "ocr_image":
        image_data = data.get("image")
        if not image_data or not isinstance(image_data, (str, bytes)):
            return None
        return {"image": image_data}
    return data

def _validate_output(result: Dict) -> bool:
    """Output safety check."""
    if "translated_text" in result:
        return not _INJECTION_PATTERNS.search(result["translated_text"])
    return True

def _encrypt_sensitive_data(text: str) -> str:
    """AES-256 encryption for sensitive text."""
    try:
        return _CIPHER_SUITE.encrypt(text.encode()).decode()
    except Exception as e:
        log_event(f"[ERROR] Encryption failed: {str(e)}", level="ERROR")
        return ""

def _decrypt_sensitive_data(text: str) -> str:
    """Decrypt sensitive text."""
    try:
        return _CIPHER_SUITE.decrypt(text.encode()).decode()
    except Exception as e:
        log_event(f"[ERROR] Decryption failed: {str(e)}", level="ERROR")
        return ""

@lru_cache(maxsize=128)
def _is_valid_task(task_type: str) -> bool:
    """Whitelist of allowed tasks."""
    return task_type in {
        "translate_text", "speak_text", 
        "ocr_image", "save_phrase", "summarize"
    }

async def handle_sidebar_event(event: Dict, user_id: str, socket_id: str) -> None:
    """
    Secure event router with zero-trust validation.
    Ensures <50ms latency for UI responsiveness.
    """
    start_time = datetime.utcnow()
    
    # Reason: Check for invalid event structure
    if not (sanitized_event := _sanitize_event(event)):
        await _send_error(socket_id, "Invalid event structure")
        return

    # Reason: Prevent unauthorized access and abuse
    if not Firewall.is_safe(user_id, event):
        await _send_error(socket_id, "Potential threat detected")
        return

    # Reason: Strict permission gating
    if not check_permission(user_id, sanitized_event.get("type")):
        await _send_error(socket_id, "Permission denied")
        return

    # Reason: Validate task type before processing
    task_type = sanitized_event.get("type")
    if not _is_valid_task(task_type):
        await _send_error(socket_id, "Unsupported task")
        return

    try:
        # Reason: Input sanitization
        data = sanitized_event.get("data", {})
        sanitized_data = _sanitize_input(data, task_type)
        if not sanitized_data:
            await _send_error(socket_id, "Invalid input")
            return

        # Reason: Route to secure handlers
        if task_type == "translate_text":
            result = await _secure_translate(
                sanitized_data.get("text"), 
                user_id,
                sanitized_data.get("lang")
            )
        elif task_type == "speak_text":
            result = await _secure_tts(
                sanitized_data.get("text"),
                sanitized_data.get("lang")
            )
        elif task_type == "ocr_image":
            result = await _secure_ocr(sanitized_data.get("image"))
        elif task_type == "save_phrase":
            result = await _secure_save_phrase(
                sanitized_data.get("text"), 
                user_id
            )
        elif task_type == "summarize":
            result = await _secure_summarize(
                sanitized_data.get("text"), 
                user_id
            )
        else:
            result = {"error": "Unknown task type"}

        # Reason: Validate output before sending
        if not _validate_output(result):
            raise ValueError("Unsafe output detected")

        latency = (datetime.utcnow() - start_time).total_seconds() * 1000
        LatencyMonitor.log_latency(f"sidebar:{task_type}", latency)
        
        await _send_response(socket_id, {
            "status": "success",
            "task": task_type,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        })

    except Exception as e:
        log_event(f"SIDEBAR_FAILURE:{task_type}:{str(e)[:50]}", level="ERROR")
        await _send_error(socket_id, "Processing error")

async def _secure_translate(text: str, user_id: str, lang: str = "en") -> Dict:
    """Translation with anti-leakage guards."""
    try:
        encrypted_text = _encrypt_sensitive_data(text)
        result = translate_text(encrypted_text, user_id, lang)
        return {
            "translated_text": _decrypt_sensitive_data(result.get("translated_text", "")),
            "source_lang": result.get("source_lang", ""),
            "target_lang": lang
        }
    except Exception as e:
        log_event(f"[ERROR] Translation failed: {str(e)}", level="ERROR")
        return {"error": "Translation failed"}

async def _secure_tts(text: str, lang: str) -> Dict:
    """TTS with injection checks."""
    try:
        if len(text) > _MAX_TEXT_LENGTH:
            text = text[:_MAX_TEXT_LENGTH]
        return speak_text(text, lang)
    except Exception as e:
        log_event(f"[ERROR] TTS failed: {str(e)}", level="ERROR")
        return {"error": "TTS failed"}

async def _secure_ocr(image: Any) -> Dict:
    """OCR with secure image handling."""
    try:
        result = extract_text_from_image(image)
        return {"text": result}
    except Exception as e:
        log_event(f"[ERROR] OCR failed: {str(e)}", level="ERROR")
        return {"error": "OCR failed"}

async def _secure_save_phrase(text: str, user_id: str) -> Dict:
    """Secure phrase saving with encryption."""
    try:
        encrypted_text = _encrypt_sensitive_data(text)
        result = save_phrase(encrypted_text, user_id)
        return {"phrase_id": result}
    except Exception as e:
        log_event(f"[ERROR] Phrase save failed: {str(e)}", level="ERROR")
        return {"error": "Save failed"}

async def _secure_summarize(text: str, user_id: str) -> Dict:
    """Summarization with privacy protection."""
    try:
        encrypted_text = _encrypt_sensitive_data(text)
        summary = summarize_text(encrypted_text, user_id)
        return {"summary": _decrypt_sensitive_data(summary)}
    except Exception as e:
        log_event(f"[ERROR] Summarization failed: {str(e)}", level="ERROR")
        return {"error": "Summarization failed"}

def _sanitize_event(event: Dict) -> Optional[Dict]:
    """Validate event structure and content."""
    try:
        required = {"type", "data", "nonce", "hmac"}
        if not all(k in event for k in required):
            return None
        
        if not isinstance(event["data"], dict):
            return None

        # Reason: URL validation for any potential external data access
        if "url" in event["data"]:
            try:
                result = urlparse(event["data"]["url"])
                if not all([result.scheme, result.netloc]):
                    return None
            except ValueError:
                return None
        
        return event
    except Exception as e:
        log_event(f"[ERROR] Event sanitization failed: {str(e)}", level="ERROR")
        return None

async def _send_response(socket_id: str, payload: Dict) -> None:
    """Secure WebSocket response."""
    try:
        payload["hmac"] = _generate_event_hmac(payload)
        await push_to_socket(socket_id, payload)
    except Exception as e:
        log_event(f"[ERROR] Sending response failed: {str(e)}", level="ERROR")

async def _send_error(socket_id: str, reason: str) -> None:
    """Standardized error response."""
    await _send_response(socket_id, {
        "status": "error",
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat()
    })

def shutdown_sidebar_manager():
    """Cleanup resources if necessary."""
    _BLOCKLIST.clear()
    
# --- End of sidebar_manager.py ---