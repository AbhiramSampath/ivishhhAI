# backend/services/camera_service.py
# 🔒 Final, Secure Camera Service for Ivish AI
# 🚀 Refactored Code

import asyncio
import uuid
import time
import os
import cv2
import numpy as np
from PIL import Image, ImageFilter
from io import BytesIO
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone
import hmac
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor
from fastapi import HTTPException
from functools import partial

# 📦 Corrected Project Imports
from ....camera_translation.ocr_engine import detect_text_from_image
from ....ai_models.translation.dialect_adapter import detect_language
from ....ai_models.translation.mt_translate import translate_text
from ....ai_control.safety_decision_manager import evaluate_safety
from ..utils.logger import log_event
from ..utils.rate_meter import rate_meter
from ....security.blockchain.blockchain_utils import log_to_blockchain
from ....security.intrusion_prevention.counter_response import blackhole_response_action, rotate_endpoint
from ....security.firewall import CameraFirewall, AudioThreatLevel
from ....security.blockchain.zkp_handler import ZKPAuthenticator

# 🧱 Global Config
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "False").lower() == "true"
ENABLE_HONEYPOT = os.getenv("ENABLE_HONEYPOT", "False").lower() == "true"
MAX_IMAGE_SIZE = int(os.getenv("MAX_IMAGE_SIZE_MB", "5")) * 1024 * 1024
MIN_FRAME_INTERVAL = float(os.getenv("MIN_FRAME_INTERVAL_SEC", "0.05"))
THREAD_POOL_SIZE = int(os.getenv("THREAD_POOL_SIZE", "4"))
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", "5"))

_FRAME_HMAC_KEY = os.getenv("FRAME_HMAC_KEY", None)
_DEVICE_HASH_SALT = os.getenv("DEVICE_HASH_SALT", None)
if not _FRAME_HMAC_KEY or not _DEVICE_HASH_SALT:
    raise RuntimeError("FRAME_HMAC_KEY and DEVICE_HASH_SALT not found in environment.")

_FRAME_HMAC_KEY = _FRAME_HMAC_KEY.encode()
_DEVICE_HASH_SALT = _DEVICE_HASH_SALT.encode()

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "firewall": CameraFirewall(),
    "threat_level": 0,
    "executor": ThreadPoolExecutor(THREAD_POOL_SIZE)
}
zkp_authenticator = ZKPAuthenticator()
logger = logging.getLogger("CameraService")

# 🔒 Security Utilities
def _hash_device_id(device_id: str) -> str:
    """GDPR-compliant device hashing."""
    return hmac.new(
        _DEVICE_HASH_SALT,
        device_id.encode(),
        hashlib.sha3_256
    ).hexdigest()

def _generate_integrity_hash(*values) -> str:
    """Tamper-proof hashing for secure logging."""
    return hashlib.sha3_256("".join(str(v) for v in values).encode()).hexdigest()

def _generate_frame_seal(image_data: bytes) -> str:
    """Creates a tamper-evident seal for image frames."""
    h = hmac.new(_FRAME_HMAC_KEY, image_data, hashlib.sha3_256)
    return h.hexdigest()

def _verify_image_integrity(image_bytes: bytes) -> bool:
    """Validates image structure and prevents malformed inputs."""
    try:
        if len(image_bytes) > MAX_IMAGE_SIZE:
            return False
        img = Image.open(BytesIO(image_bytes))
        img.verify()
        return True
    except Exception:
        return False

def _is_sensitive_content(image_bytes: bytes) -> bool:
    """Detects sensitive or potentially offensive content."""
    # Placeholder for a real NSFW model or content detection service
    return b'adult_content_marker' in image_bytes

def _sanitize_ocr_text(text: str) -> str:
    """Prevents XSS and injection in OCR output."""
    injection_patterns = [
        '<?', '<script', 'SELECT', 'os.system', 'subprocess.call', 'eval('
    ]
    for pattern in injection_patterns:
        text = text.replace(pattern, '')
    return text.strip()

def _increment_threat_level():
    """Increase threat level and trigger defense if needed."""
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        asyncio.create_task(_anti_tamper_protocol())

async def _anti_tamper_protocol():
    """Active defense against injection or tampering."""
    log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
    if ENABLE_HONEYPOT:
        await _trigger_honeypot()
    blackhole_response_action()
    rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

async def _trigger_honeypot():
    """Deceive attackers with fake image processing."""
    await process_camera_image(
        b"malformed_image_data",
        zkp_token="fake_zkp",
        device_id="attacker_device"
    )

def _enhance_for_ocr_sync(image_np: np.ndarray) -> np.ndarray:
    """Sync image enhancement pipeline for thread pool."""
    try:
        # Convert to grayscale
        gray = cv2.cvtColor(image_np, cv2.COLOR_RGB2GRAY)
        # Apply sharpness and contrast
        enhanced = cv2.addWeighted(gray, 1.5, cv2.GaussianBlur(gray, (3, 3), 0), -0.5, 0)
        return enhanced
    except Exception as e:
        logger.error(f"Image enhancement failed: {e}")
        return image_np

# 🧠 Camera Service Core
async def process_camera_image(
    image_bytes: bytes,
    translate: bool = True,
    target_lang: str = "en",
    device_id: Optional[str] = None,
    zkp_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Hardened camera processing pipeline.
    """
    session_id = str(uuid.uuid4())
    user_id = "anonymous"
    if device_id:
        user_id = _hash_device_id(device_id)

    if await rate_meter.track_call(user_id, source="camera_ocr"):
        log_event("Rate limit exceeded", level="WARNING")
        raise HTTPException(429, detail="Too many requests")

    if not _verify_image_integrity(image_bytes):
        log_event("Invalid image structure", level="WARNING")
        raise HTTPException(400, detail="Malformed image data")

    if _is_sensitive_content(image_bytes) and not await zkp_authenticator.verify_proof_async(user_id, zkp_token):
        log_event("ZKP required for sensitive image", level="WARNING")
        raise HTTPException(403, detail="ZKP token required for sensitive content")

    try:
        image = Image.open(BytesIO(image_bytes)).convert("RGB")
        
        loop = asyncio.get_running_loop()
        enhanced_np = await loop.run_in_executor(
            SECURITY_CONTEXT["executor"],
            partial(_enhance_for_ocr_sync, image_np=np.array(image))
        )
        
        ocr_result = await detect_text_from_image(enhanced_np, session_id)
        raw_text = " ".join([_sanitize_ocr_text(tb["text"]) for tb in ocr_result["text_boxes"]])
        source_lang = await detect_language(raw_text) or "en"
        
        translated_text = None
        if translate and source_lang != target_lang:
            translated_text = await _safe_translate(
                text=raw_text,
                src=source_lang,
                tgt=target_lang,
                session_id=session_id
            )

        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain("camera_processing", {
                "session_id": session_id,
                "source_lang": source_lang,
                "target_lang": target_lang,
                "text_hash": _generate_integrity_hash(raw_text),
                "timestamp": datetime.utcnow().isoformat()
            })

        return {
            "session_id": session_id,
            "detected_language": source_lang,
            "original_text": raw_text,
            "translated_text": translated_text,
            "bounding_boxes": ocr_result["text_boxes"],
            "integrity_seal": _generate_frame_seal(image_bytes),
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Camera processing failed: {e}")
        _increment_threat_level()
        raise HTTPException(500, detail="Secure processing error")

async def _safe_translate(text: str, src: str, tgt: str, session_id: str) -> Optional[str]:
    """Protected translation with safety checks."""
    try:
        safety_check = await evaluate_safety(text=text, direction="input", session_id=session_id)
        if safety_check["status"] == "blocked":
            return None

        translated = await asyncio.wait_for(translate_text(text, src=src, tgt=tgt), timeout=1.0)
        
        post_check = await evaluate_safety(text=translated, direction="output", session_id=session_id)
        if post_check["status"] == "blocked":
            log_event(f"Translation blocked: {post_check['reason']}", level="WARNING")
            return None
        return _sanitize_ocr_text(translated)
    except Exception as e:
        log_event(f"Translation failed: {e}", level="ERROR")
        _increment_threat_level()
        return None

async def get_text_overlay_data(
    image_bytes: bytes,
    target_lang: str = "en",
    device_id: Optional[str] = None,
    zkp_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Returns structured AR overlay data.
    """
    if not _verify_image_integrity(image_bytes):
        raise HTTPException(400, detail="Image integrity check failed")

    if _is_sensitive_content(image_bytes) and not await zkp_authenticator.verify_proof_async(device_id, zkp_token):
        raise HTTPException(403, detail="ZKP required for AR overlay")
    
    try:
        result = await process_camera_image(image_bytes=image_bytes, translate=True, target_lang=target_lang, device_id=device_id, zkp_token=zkp_token)
        return {
            "overlay": {
                "text": result["translated_text"],
                "boxes": result["bounding_boxes"],
                "language": result["detected_language"],
                "timestamp": result["timestamp"]
            },
            "style": {
                "font": "Noto Sans" if result["detected_language"] in ["ja", "zh", "hi"] else "Roboto",
                "color": "#ffffff",
                "background": "#000000"
            }
        }
    except Exception as e:
        log_event(f"Overlay generation failed: {e}", level="ERROR")
        _increment_threat_level()
        raise HTTPException(500, detail="Overlay generation failed")