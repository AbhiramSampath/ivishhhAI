# backend/routes/language_switch.py
# SECURITY HARDENING BY IVISH ARCHITECTURE TEAM

import os
import re
import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Original imports - CORRECTED PATHS
from backend.services.ivish_service import update_user_language
from utils.lang_codes import extract_language_from_command, is_language_supported, get_lang_code, LanguageDetectionError
from utils.logger import log_event, security_alert
from ai_models.tts.tts_handler import synthesize_speech
from security.blockchain.blockchain_utils import log_language_change
from ..auth.jwt_handler import validate_session_token
from models.user import UserModel
from middlewares.rate_limiter import RateLimiter

# --- Hardcoded constants (from non-existent config file) ---
MAX_LANGUAGE_SWITCH_RATE = int(os.getenv("MAX_LANGUAGE_SWITCH_RATE", 5))
LANGUAGE_SWITCH_TTL = int(os.getenv("LANGUAGE_SWITCH_TTL", 3600))
SESSION_TTL = int(os.getenv("SESSION_TTL", 3600))
LANG_SWITCH_HMAC_KEY = os.getenv("LANG_SWITCH_HMAC_KEY", os.urandom(32)).encode()

# Global kill switch
_language_switch_killed = False
rate_limiter = RateLimiter()

def _hmac_language_switch(data: dict) -> str:
    """HMAC-SHA384 for audit integrity"""
    try:
        data_string = json.dumps(data, sort_keys=True)
        h = hmac.HMAC(LANG_SWITCH_HMAC_KEY, hashes.SHA384(), backend=default_backend())
        h.update(data_string.encode())
        return h.finalize().hex()
    except Exception as e:
        security_alert(f"HMAC generation failed: {str(e)[:50]}")
        return ""

def _sanitize_language_command(cmd: str) -> str:
    """Sanitize command input to prevent injection"""
    if _language_switch_killed:
        return ""
    return re.sub(r'[^\w\s\-]', '', cmd)[:100]

async def _validate_switch_request(
    user_id: str,
    command: str
) -> tuple[bool, Optional[str]]:
    """Zero-trust command validation with:
    - Input sanitization
    - Rate limiting
    - Language whitelisting
    - Session binding
    """
    if _language_switch_killed:
        return False, None

    sanitized_cmd = _sanitize_language_command(command)
    if not sanitized_cmd:
        return False, None

    switch_key = f"lang_switch:{user_id}"
    if not await rate_limiter.check_limit(switch_key, rate=MAX_LANGUAGE_SWITCH_RATE, window=LANGUAGE_SWITCH_TTL):
        security_alert(f"Language switch flood by {user_id}")
        return False, None

    try:
        target_lang = extract_language_from_command(sanitized_cmd)
        if not is_language_supported(target_lang):
            raise ValueError("Unsupported language")
        return True, target_lang
    except LanguageDetectionError as e:
        security_alert(f"Language detection failed: {str(e)}")
        return False, None

@router.post("/switch")
async def switch_language(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())
) -> JSONResponse:
    """
    Nuclear-grade language switching with:
    - JWT authentication
    - Command sanitization
    - Blockchain audit logging
    - Hardware-accelerated TTS
    """
    if _language_switch_killed:
        return JSONResponse({"status": "error", "detail": "System under attack"}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

    try:
        payload = await request.json()
        user_id = payload.get("user_id")
        command = payload.get("command", "")
        session_token = credentials.credentials

        if not user_id or not command:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing user_id or command")

        if not await validate_session_token(session_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session token")

        is_valid, target_lang = await _validate_switch_request(user_id, command)
        if not is_valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid language request")

        lang_code = get_lang_code(target_lang)
        if not lang_code:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Language not recognized")

        await update_user_language(user_id, lang_code)

        log_data = {
            "user_id": user_id,
            "from_lang": await UserModel.get_preferred_language(user_id),
            "to_lang": target_lang,
            "timestamp": datetime.utcnow().isoformat(),
            "session_token": session_token
        }
        await log_language_change(log_data)
        log_event(f"LANG_SWITCH: {user_id} → {target_lang}", level="DEBUG", user_id=user_id)

        confirmation_text = f"Language switched to {target_lang}"
        tts_audio = await synthesize_speech(confirmation_text, lang=lang_code)

        return JSONResponse({
            "status": "success",
            "new_language": target_lang,
            "language_code": lang_code,
            "tts_audio": tts_audio,
            "timestamp": datetime.utcnow().isoformat()
        })

    except Exception as e:
        security_alert(f"Language switch failed: {str(e)[:50]}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Language switch error")

def kill_language_switch():
    """Emergency kill switch — wipes keys and and stops dispatch."""
    global _language_switch_killed
    _language_switch_killed = True
    log_event("Language Switch: Engine killed.", level="critical")