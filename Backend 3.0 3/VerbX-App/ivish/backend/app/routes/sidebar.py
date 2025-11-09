# backend/routes/sidebar.py
# 🔒 Nuclear-Grade Sidebar Integration | Zero-Trust Translation | Secure Streaming

from fastapi import APIRouter, WebSocket, Request, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import time
import uuid
import os
import hmac
import hashlib
import asyncio
from collections import defaultdict

# 📦 Project Imports - CORRECTED PATHS
from backend.app.services.permission_service import check_permission
from backend.app.services.sidebar_service import process_sidebar_translation
from ai_models.emotion.emotion_handler import detect_emotion
from utils.logger import log_event
from utils.lang_codes import get_supported_languages
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import BlackholeRouter, rotate_endpoint
from security.firewall import Firewall as SidebarFirewall
from middlewares.rate_limiter import RateLimiter
from backend.app.services.ivish_service import end_session as end_ivish_session
from ..auth.jwt_handler import get_user_id_from_jwt

# 🧱 Global Config - Defined locally as config file is not in PDF
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "True").lower() == "true"
ENABLE_HONEYPOT = os.getenv("ENABLE_HONEYPOT", "True").lower() == "true"
ENABLE_ENDPOINT_MUTATION = os.getenv("ENABLE_ENDPOINT_MUTATION", "True").lower() == "true"
MIN_QUERY_TIME = float(os.getenv("MIN_QUERY_TIME", "0.1"))
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", "5"))
MAX_STREAM_MESSAGES = int(os.getenv("MAX_STREAM_MESSAGES", "1000"))
MAX_STREAM_DURATION = int(os.getenv("MAX_STREAM_DURATION", "3600"))

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "firewall": SidebarFirewall(),
    "threat_level": 0,
    "last_attack_time": 0
}

_RATE_LIMITER = RateLimiter()
_BLACKHOLE_ROUTER = BlackholeRouter()
_SUPPORTED_LANGUAGES = get_supported_languages()

# 🧠 Sidebar Models
class SidebarTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=1000)
    source_lang: str = Field(..., min_length=2, max_length=5)
    target_lang: str = Field(..., min_length=2, max_length=5)
    app_id: str = Field(..., min_length=16, max_length=32)
    zkp_proof: Optional[str] = None

class StreamPayload(BaseModel):
    text: str
    source_lang: str
    target_lang: str
    app_id: str
    session_id: str

# 🔒 Security Utilities - CONSOLIDATED & CORRECTED
def _get_hw_key() -> bytes:
    hw_factors = [os.getenv("HW_FINGERPRINT", "")]
    return hashlib.pbkdf2_hmac('sha256', "|".join(hw_factors).encode(), os.urandom(16), 100000)[:32]

def _generate_session_id() -> str:
    return hmac.new(_get_hw_key(), datetime.utcnow().isoformat().encode(), hashlib.sha3_256).hexdigest()

def _hash_app_id(app_id: str) -> str:
    return hmac.new(os.getenv("APP_HASH_SALT", "").encode(), app_id.encode(), hashlib.sha3_256).hexdigest()

def _generate_integrity_hash(*values) -> str:
    return hashlib.sha3_256("".join(values).encode()).hexdigest()

def _generate_response_seal(text: str, emotion: str) -> str:
    return hmac.new(os.getenv("RESPONSE_SEAL_KEY", os.urandom(32)).encode(), (text + emotion).encode(), hashlib.sha3_256).hexdigest()

async def _increment_threat_level():
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        await _anti_tamper_protocol()

async def _anti_tamper_protocol():
    log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
    if ENABLE_HONEYPOT:
        asyncio.create_task(_trigger_honeypot())
    await _BLACKHOLE_ROUTER.trigger()
    if ENABLE_ENDPOINT_MUTATION:
        rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

async def _trigger_honeypot():
    await translate_sidebar_text(
        req=SidebarTextRequest(
            text="SELECT * FROM users; DROP TABLE",
            source_lang="en",
            target_lang="es",
            app_id="fake_app"
        ),
        request=Request(scope={"headers": {"authorization": "fake_token", "x-device-hash": "fake"}}),
        user_id="honeypot_user"
    )

def _sanitize_text(text: str) -> str:
    injection_patterns = ['<?', '<?php', '<script', 'SELECT * FROM', 'os.system', 'subprocess.call', 'eval(']
    for pattern in injection_patterns:
        text = text.replace(pattern, '')
    return text.strip()

# 🧠 Sidebar API Core
router = APIRouter(
    prefix="/sidebar",
    tags=["Sidebar Integration"],
    responses={403: {"description": "Forbidden"}}
)

# 🧩 Sidebar Routes
@router.post("/translate", response_model=Dict[str, Any])
async def translate_sidebar_text(
    req: SidebarTextRequest,
    request: Request,
    user_id: str = Depends(get_user_id_from_jwt)
):
    if not await _RATE_LIMITER.check_limit(user_id, rate=100, window=3600):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")
    
    if not await check_permission(
        user_id=user_id,
        permission_type="overlay_permission",
        token=request.headers.get("authorization")
    ):
        log_event(f"Sidebar auth failed for {req.app_id}", level="WARNING")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "App not authorized")

    try:
        emotion = await detect_emotion(req.text)
        translated = await process_sidebar_translation(req.text, req.source_lang, req.target_lang, emotion)

        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain("sidebar_translate", payload={
                "app_id_hash": _hash_app_id(req.app_id),
                "source_lang": req.source_lang,
                "target_lang": req.target_lang,
                "text_hash": _generate_integrity_hash(req.text),
                "timestamp": datetime.utcnow().isoformat()
            })

        return {
            "translated_text": _sanitize_text(translated),
            "emotion": emotion,
            "integrity_check": _generate_response_seal(translated, emotion["label"])
        }

    except Exception as e:
        log_event(f"Sidebar translation failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Translation service unavailable")

@router.websocket("/stream-subtitles")
async def stream_subtitles(
    websocket: WebSocket,
    user_id: str = Depends(get_user_id_from_jwt),
    app_id: str = None
):
    try:
        await websocket.accept()
        session_id = _generate_session_id()

        if not user_id or not app_id:
            log_event("Missing token or app_id", level="WARNING")
            await _kill_switch(session_id, websocket)

        if not await check_permission(user_id, "overlay_permission"):
            log_event(f"Unauthorized stream for {app_id}", level="WARNING")
            await _kill_switch(session_id, websocket)

        message_counter = 0
        start_time = time.time()
        while True:
            payload = await websocket.receive_json()
            if (time.time() - start_time) > MAX_STREAM_DURATION:
                log_event("Stream duration exceeded", level="WARNING")
                await _kill_switch(session_id, websocket)
            if message_counter > MAX_STREAM_MESSAGES:
                log_event("Stream message limit exceeded", level="WARNING")
                await _kill_switch(session_id, websocket)
            
            if not all(f in payload for f in ["text", "source_lang", "target_lang", "app_id"]):
                log_event("Invalid stream payload", level="WARNING")
                await _kill_switch(session_id, websocket)
            
            result = await _process_stream_payload(payload, session_id, user_id)
            await websocket.send_json(result)
            message_counter += 1

    except Exception as e:
        log_event(f"WebSocket stream failed: {str(e)}", level="ERROR")
        await _kill_switch(session_id, websocket)

async def _process_stream_payload(payload: Dict[str, Any], session_id: str, user_id: str) -> Dict[str, Any]:
    text = _sanitize_text(payload.get("text", ""))
    source_lang = payload.get("source_lang", "auto")
    target_lang = payload.get("target_lang", "en")
    app_id = payload.get("app_id", "unknown")
    
    emotion = await detect_emotion(text)
    if emotion.get("confidence", 0) < 0.7:
        emotion = {"label": "neutral", "confidence": 1.0}
    
    translated = await process_sidebar_translation(text, source_lang, target_lang, emotion)
    
    if not translated:
        translated = "Translation unavailable"
    
    if ENABLE_BLOCKCHAIN_LOGGING:
        await log_to_blockchain("sidebar_stream", payload={
            "user_id": user_id, "app_id": app_id, "text_hash": _generate_integrity_hash(text),
            "translated_hash": _generate_integrity_hash(translated), "timestamp": datetime.utcnow().isoformat()
        })
    
    return {
        "subtitle": translated, "emotion": emotion,
        "integrity_check": _generate_response_seal(translated, str(emotion)),
        "session_id": session_id
    }

async def _kill_switch(session_id: str, websocket: WebSocket):
    await end_ivish_session(session_id)
    await websocket.close(code=1008, reason="Security violation")

@router.get("/languages", response_model=Dict[str, List[str]])
async def get_supported_languages_route():
    return {"languages": list(_SUPPORTED_LANGUAGES)}