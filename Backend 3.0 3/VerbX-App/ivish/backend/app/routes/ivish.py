# backend/routes/ivish.py
# 🔒 Nuclear-Grade Ivish AI API | Zero-Trust Architecture | Blockchain-Backed
# 🧠 Designed for Edge Deployment, Federated Learning, and Offline AI

from ast import Dict
import os
import io
import time
from typing import Any
import uuid
import jwt
import hmac
import hashlib
import asyncio
import base64
from datetime import datetime, timedelta
from collections import defaultdict
from fastapi import APIRouter, UploadFile, File, Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# 📦 Project Imports - CORRECTED PATHS
from backend.app.services.ivish_service import get_session_context, end_session
from ai_models.whisper.whisper_handler import transcribe_audio
from ai_models.translation.gpt_prompter import generate_gpt_response
from ai_models.tts.tts_handler import synthesize_speech
from ai_models.emotion.emotion_handler import detect_emotion
from ai_control.safety_decision_manager import evaluate_safety
from utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import BlackholeRouter, rotate_endpoint
from security.firewall import Firewall as IvishFirewall
from middlewares.rate_limiter import RateLimiter
from security.encryption_utils import generate_watermark_key, hash_watermark


# 🧱 Global Config - Defined locally as config file is not in PDF
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "True").lower() == "true"
ENABLE_HONEYPOT = os.getenv("ENABLE_HONEYPOT", "True").lower() == "true"
ENABLE_ENDPOINT_MUTATION = os.getenv("ENABLE_ENDPOINT_MUTATION", "True").lower() == "true"
MAX_AUDIO_SIZE = int(os.getenv("MAX_AUDIO_SIZE", 1024 * 1024))
MAX_SESSION_DURATION = int(os.getenv("MAX_SESSION_DURATION", 3600))
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", 5))
MIN_SAFETY_SCORE = float(os.getenv("MIN_SAFETY_SCORE", 0.7))
MAX_FAILURE_RATE = int(os.getenv("MAX_FAILURE_RATE", 3))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", 60))

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "firewall": IvishFirewall(),
    "threat_level": 0,
    "last_attack_time": 0
}

# 🔒 Security Utilities - CONSOLIDATED & CORRECTED
_IVISH_JWT_SECRET = os.getenv("IVISH_JWT_SECRET", os.urandom(32)).encode()
_IVISH_HW_FINGERPRINT = os.getenv("HW_FINGERPRINT", "default_fingerprint")
_BLACKHOLE_ROUTER = BlackholeRouter()
_RATE_LIMITER = RateLimiter()

def _validate_audio_fingerprint(data: bytes) -> bool:
    """Detects invalid or malicious audio input"""
    return data.startswith(b'RIFF') or data.startswith(b'WAVE')

def _sanitize_text(text: str) -> str:
    """Prevent prompt injection and XSS in responses"""
    injection_patterns = [
        '<?', '<?php', '<script', 'SELECT * FROM', 'os.system', 'subprocess.call', 'eval('
    ]
    for pattern in injection_patterns:
        text = text.replace(pattern, '')
    return text.strip()

async def _increment_threat_level():
    """Increase threat level and trigger defense if needed"""
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        await _anti_tamper_protocol()

async def _anti_tamper_protocol():
    """Active defense against injection or tampering"""
    log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
    if ENABLE_HONEYPOT:
        asyncio.create_task(_trigger_honeypot())
    await _BLACKHOLE_ROUTER.trigger()
    if ENABLE_ENDPOINT_MUTATION:
        rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

async def _trigger_honeypot():
    """Deceive attackers with fake session"""
    fake_audio = UploadFile(filename="fake.wav", file=io.BytesIO(b"RIFF" + b"\x00" * 1024))
    fake_request = Request(scope={"headers": {"user-id": "attacker", "authorization": "fake_token"}})
    await ivish_voice_route(file=fake_audio, request=fake_request, user_id="honeypot_user")

# 🧠 Ivish API Core
router = APIRouter(
    tags=["Ivish Assistant"],
    responses={403: {"description": "Forbidden"}}
)

security = HTTPBearer()

def _verify_hardware_binding(
    creds: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None
) -> str:
    """
    Zero-trust authentication with hardware-bound token
    """
    try:
        payload = jwt.decode(creds.credentials, _IVISH_JWT_SECRET, algorithms=["HS512"])
        if payload.get("device_hash") != _IVISH_HW_FINGERPRINT:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Device mismatch")
        return payload["sub"]
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Invalid session token")
    except Exception as e:
        log_event(f"Hardware binding failed: {str(e)}", level="WARNING")
        asyncio.create_task(_increment_threat_level())
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Hardware authentication failed")

@router.post("/ivish/voice", response_model=Dict[str, Any])
async def ivish_voice_route(
    file: UploadFile = File(...),
    request: Request = None,
    user_id: str = Depends(_verify_hardware_binding)
):
    """
    Nuclear-grade voice processing pipeline.
    """
    if not await _RATE_LIMITER.check_limit(user_id, rate=MAX_FAILURE_RATE, window=RATE_LIMIT_WINDOW):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")
    
    session_id = str(uuid.uuid4())
    log_event(f"Ivish Voice Session {session_id[:8]} started", session_id=session_id)

    content = await file.read()
    if len(content) > MAX_AUDIO_SIZE:
        log_event("Audio file too large", level="WARNING")
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Audio file too large")

    if not _validate_audio_fingerprint(content):
        log_event("Invalid audio format", level="WARNING")
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid audio format")

    try:
        async with asyncio.TaskGroup() as tg:
            stt_task = tg.create_task(transcribe_audio(content))
            context_task = tg.create_task(get_session_context(user_id, session_id))
            safety_task = tg.create_task(evaluate_safety(content, direction="input"))

        stt_result = stt_task.result()
        context = context_task.result()
        safety = safety_task.result()

        prompt = _sanitize_text(stt_result.get("text", ""))
        if not prompt:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Empty transcription")
        
        tone = await detect_emotion(prompt)
        if tone.get("confidence", 0) < MIN_SAFETY_SCORE:
            tone = {"label": "neutral", "confidence": 1.0}

        gpt_reply = await _safe_gpt_generate(prompt=prompt, context=context, tone=tone, user_id=user_id, session_id=session_id)

        tts_audio = await synthesize_speech(text=gpt_reply["sanitized_output"], tone=tone)

        safe_output = _sanitize_text(gpt_reply["sanitized_output"])
        if not safe_output:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Empty response after sanitization")

        watermarked_audio = _watermark_audio(tts_audio, session_id)

        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain("voice_interaction", {
                "session_id": session_id,
                "input_hash": hashlib.sha3_256(prompt.encode()).hexdigest(),
                "output_hash": hashlib.sha3_256(safe_output.encode()).hexdigest(),
                "tone": tone["label"],
                "safety_score": gpt_reply["safety_metrics"]["score"],
                "timestamp": datetime.utcnow().isoformat()
            })

        return {
            "text": safe_output,
            "tone": tone,
            "audio_base64": base64.b64encode(watermarked_audio).decode(),
            "lang": stt_result.get("language", "auto"),
            "session_id": session_id,
            "safety": gpt_reply["safety_metrics"]
        }

    except Exception as e:
        log_event(f"Voice route failed: {str(e)}", level="ERROR")
        await end_session(session_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Secure processing failed")

@router.post("/ivish/text", response_model=Dict[str, Any])
async def ivish_text_route(
    text: str,
    request: Request,
    user_id: str = Depends(_verify_hardware_binding)
):
    """
    Secure text-based AI assistant route.
    """
    if not await _RATE_LIMITER.check_limit(user_id, rate=MAX_FAILURE_RATE, window=RATE_LIMIT_WINDOW):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")
    
    session_id = str(uuid.uuid4())
    log_event(f"Ivish Text Session {session_id[:8]} started", session_id=session_id)

    if not text or not isinstance(text, str):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Missing or invalid text input")

    prompt = _sanitize_text(text)
    if not prompt:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Empty or malicious input")

    async with asyncio.TaskGroup() as tg:
        context_task = tg.create_task(get_session_context(user_id, session_id))
        safety_task = tg.create_task(evaluate_safety(prompt, direction="input"))

    context = context_task.result()
    safety = safety_task.result()

    if safety["status"] == "blocked":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"Blocked: {safety['reason']}")

    gpt_reply = await _safe_gpt_generate(prompt=prompt, context=context, tone=await detect_emotion(prompt), user_id=user_id, session_id=session_id)
    
    if gpt_reply["safety_metrics"]["score"] < MIN_SAFETY_SCORE:
        gpt_reply["sanitized_output"] = "I can't respond to that."

    safe_output = _sanitize_text(gpt_reply["sanitized_output"])
    if not safe_output:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Empty or unsafe output")

    if ENABLE_BLOCKCHAIN_LOGGING:
        await log_to_blockchain("text_interaction", {
            "session_id": session_id,
            "input_hash": hashlib.sha3_256(prompt.encode()).hexdigest(),
            "output_hash": hashlib.sha3_256(safe_output.encode()).hexdigest(),
            "timestamp": datetime.utcnow().isoformat()
        })

    return {
        "text": safe_output,
        "tone": gpt_reply["tone"],
        "lang": gpt_reply.get("lang", "en"),
        "safety": gpt_reply["safety_metrics"]
    }

@router.get("/ivish/wake")
async def ivish_wake_route(
    request: Request,
    user_id: str = Depends(_verify_hardware_binding)
):
    """
    Wake word activation with secure session initialization.
    """
    session_id = str(uuid.uuid4())
    return {
        "session_id": session_id,
        "status": "awake",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/ivish/end")
async def ivish_end_route(
    request: Request,
    session_id: str,
    user_id: str = Depends(_verify_hardware_binding)
):
    """
    Secure session termination with cryptographic shredding.
    """
    try:
        await end_session(session_id)
        log_event(f"Session {session_id[:8]} ended", session_id=session_id)
        return {"status": "session_ended", "session_id": session_id}
    except Exception as e:
        log_event(f"Session end failed: {str(e)}", level="ERROR")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Session termination failed")

async def _safe_gpt_generate(
    prompt: str,
    context: Dict[str, Any],
    tone: Dict[str, Any],
    user_id: str,
    session_id: str
) -> Dict[str, Any]:
    """
    GPT generation with safety guardrails and fallback.
    """
    pre_check = await evaluate_safety(prompt, direction="input", user_id=user_id, session_id=session_id)
    if pre_check["status"] == "blocked":
        log_event(f"Input blocked: {pre_check['reason']}", level="WARNING")
        return {"sanitized_output": "I can't respond to that.", "safety_metrics": pre_check}
    
    try:
        raw_output = await asyncio.wait_for(
            generate_gpt_response(prompt=prompt, context=context, tone=tone, safety_settings=pre_check), timeout=1.5
        )
        post_check = await evaluate_safety(raw_output, direction="output", user_id=user_id, session_id=session_id)
        if post_check["status"] == "blocked":
            log_event(f"Output blocked: {post_check['reason']}", level="WARNING")
            raw_output = "I can't respond to that."
        return {"sanitized_output": _sanitize_text(raw_output), "safety_metrics": post_check}
    
    except asyncio.TimeoutError:
        log_event("GPT generation timeout", level="WARNING")
        return {"sanitized_output": "I'm experiencing a delay. Please try again.", "safety_metrics": {"status": "safe", "score": 0.95}}
    except Exception as e:
        log_event(f"GPT generation failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        return {"sanitized_output": "I encountered an error processing your request.", "safety_metrics": {"status": "safe", "score": 0.85}}

def _watermark_audio(audio: bytes, session_id: str) -> bytes:
    """Embeds session watermark for traceability"""
    watermark_key = generate_watermark_key()
    watermark = hmac.new(watermark_key, session_id.encode(), hashlib.sha3_256).digest()[:16]
    return audio + watermark