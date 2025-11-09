"""
tts.py - Secure TTS Generation API for Ivish AI
"""

import os
import uuid
import time
import jwt
import hmac
import hashlib
import asyncio
import logging
import json
import numpy as np
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Optional, Union
from fastapi import APIRouter, Request, HTTPException, Header, Depends, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, validator

# Internal imports - CORRECTED PATHS
from ai_models.tts.tts_handler import synthesize_speech
from ai_models.emotion.emotion_handler import detect_emotion
from utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain
from ..auth.jwt_handler import get_current_user
from security.security import sanitize_text

# External imports - Removed non-existent
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Type aliases
TextInput = str
LanguageCode = str
ToneLabel = str
TTSRequestModel = Dict[str, Any]
TTSResponse = BytesIO

# Security: HMAC key rotation and cache directory
_AUDIO_CACHE_DIR = Path("/var/tts_cache")
_AUDIO_CACHE_DIR.mkdir(exist_ok=True, mode=0o700)
_TTS_HMAC_KEY = os.getenv("TTS_HMAC_KEY", os.urandom(32)).encode()

# --- Hardcoded constants (from non-existent config file) ---
DEFAULT_TTS_LANG = os.getenv("DEFAULT_TTS_LANG", "en")
ENABLE_EMOTION_TTS = os.getenv("ENABLE_EMOTION_TTS", "True").lower() == "true"
_CACHE_TTL = int(os.getenv("TTS_CACHE_TTL", 86400))
_SUPPORTED_LANGUAGES = ["en", "hi", "ta", "te", "kn", "bn", "gu", "ml", "mr", "ur", "ne", "si"]

router = APIRouter(
    prefix="/tts",
    tags=["speech"],
    responses={404: {"description": "Not found"}}
)

# === SECURE MODELS === #
class TTSRequest(BaseModel):
    text: TextInput = Field(..., min_length=1, max_length=5000)
    language: LanguageCode = Field(default=DEFAULT_TTS_LANG, min_length=2, max_length=5)
    tone: Optional[ToneLabel] = Field(None, min_length=2, max_length=20)
    stream: bool = False
    session_id: Optional[str] = None

    @validator('text')
    def validate_text(cls, v):
        if len(v) > 5000:
            raise ValueError("Text too long")
        return sanitize_text(v)

    @validator('tone')
    def validate_tone(cls, v):
        if v and v.lower() not in ["happy", "sad", "angry", "neutral", "excited"]:
            raise ValueError("Unsupported tone")
        return v

class TTSResponseHeaders:
    def __init__(self, request_hash: str):
        self.headers = {
            "X-Content-Type-Options": "nosniff",
            "X-TTS-Hash": request_hash,
            "Content-Security-Policy": "default-src 'self'",
        }

# === CORE SERVICES === #
class TTSEngine:
    def __init__(self):
        self._logger = logging.getLogger("tts_engine")
        self._supported_languages = _SUPPORTED_LANGUAGES
        self._cache_ttl = _CACHE_TTL

    async def generate(self, request: TTSRequest, client_ip: str, user: dict) -> BytesIO:
        try:
            lang = request.language
            if lang not in self._supported_languages:
                lang = "en"

            tone = request.tone
            if not tone and ENABLE_EMOTION_TTS:
                tone = await detect_emotion(request.text)
                if tone not in ["happy", "sad", "angry", "neutral", "excited"]:
                    tone = "neutral"

            cache_key = self._get_cache_key(request.text, lang, tone)
            if audio := await self._check_cache(cache_key):
                return audio

            audio = await synthesize_speech(text=request.text, lang=lang, tone=tone, session_id=request.session_id)
            asyncio.create_task(self._write_cache(cache_key, audio))

            await self._log_generation(text=request.text, tone=tone, lang=lang, ip=client_ip, user_id=user["id"], cache_key=cache_key)

            return BytesIO(audio)

        except Exception as e:
            self._logger.error(f"TTS generation failed: {str(e)}", exc_info=True)
            raise

    def _get_cache_key(self, text: TextInput, lang: LanguageCode, tone: Optional[ToneLabel]) -> str:
        text_hash = hashlib.sha256(text.encode()).hexdigest()
        tone_str = tone or "default"
        return f"{lang}_{tone_str}_{text_hash[:16]}"

    async def _check_cache(self, key: str) -> Optional[BytesIO]:
        cache_file = _AUDIO_CACHE_DIR / f"{key}.wav"
        if await asyncio.to_thread(cache_file.exists):
            async with asyncio.to_thread(open, cache_file, "rb") as f:
                return BytesIO(f.read())
        return None

    async def _write_cache(self, key: str, data: bytes) -> None:
        tmp_path = _AUDIO_CACHE_DIR / f"tmp_{os.urandom(4).hex()}"
        try:
            async with asyncio.to_thread(open, tmp_path, "wb") as f:
                f.write(data)
            await asyncio.to_thread(os.rename, tmp_path, _AUDIO_CACHE_DIR / f"{key}.wav")
            await asyncio.to_thread(os.chmod, _AUDIO_CACHE_DIR / f"{key}.wav", 0o600)
        except Exception as e:
            self._logger.warning(f"Cache write failed: {str(e)}")

    async def _log_generation(self, **kwargs) -> None:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "text_hash": hashlib.sha256(kwargs["text"].encode()).hexdigest(),
            "tone": kwargs["tone"],
            "lang": kwargs["lang"],
            "ip": kwargs["ip"],
            "user_id": kwargs["user_id"],
            "cache_key": kwargs["cache_key"],
            "security": {"verified": True, "system": "ivish-tts-v1"}
        }
        log_event("TTS_GENERATED", extra=log_data)
        try:
            await log_to_blockchain("tts_event", log_data)
        except Exception as e:
            self._logger.warning(f"Blockchain logging failed: {str(e)}")

# === API ROUTES === #
@router.post("/generate", response_class=StreamingResponse)
async def generate_tts(
    request: TTSRequest,
    user: dict = Depends(get_current_user),
    x_real_ip: str = Header(...),
    x_request_id: str = Header(...)
):
    try:
        tts_engine = TTSEngine()
        audio = await tts_engine.generate(request, x_real_ip, user)
        headers = TTSResponseHeaders(request_hash=hashlib.sha256(f"{x_request_id}{x_real_ip}".encode()).hexdigest()).headers
        return StreamingResponse(audio, media_type="audio/wav", headers=headers)
    except Exception as e:
        log_event("TTS_GENERATION_FAILED", level="ERROR", extra={"error": str(e), "ip": x_real_ip, "timestamp": datetime.utcnow().isoformat() + "Z"})
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="TTS generation failed")

@router.post("/stream")
async def stream_tts(
    request: TTSRequest,
    user: dict = Depends(get_current_user),
    x_real_ip: str = Header(...)
):
    try:
        text_chunks = [chunk.strip() for chunk in request.text.split(".") if chunk.strip()]
        for chunk in text_chunks:
            chunk_request = TTSRequest(text=chunk, language=request.language, tone=request.tone)
            audio = await tts_engine.generate(chunk_request, x_real_ip, user)
            yield audio.getvalue()
    except Exception as e:
        log_event("TTS_STREAM_FAILURE", level="ERROR", extra={"error": str(e)})
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="TTS streaming failed")