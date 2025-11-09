# backend/routes/stt.py
# SECURITY HARDENING BY IVISH ARCHITECTURE TEAM

import os
import re
import time
import asyncio
import hashlib
import tempfile
import aiofiles
import json
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import (
    APIRouter, 
    UploadFile, 
    File, 
    WebSocket, 
    Depends,
    HTTPException, 
    status,
    Request
)
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.websockets import WebSocketDisconnect
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Original imports - CORRECTED PATHS
from ..ai_models.whisper.whisper_handler import transcribe_audio
from ..utils.logger import log_event, security_alert
from ..security.blockchain.blockchain_utils import log_stt_usage
from ..auth.jwt_handler import validate_session_token
from ..models.user import UserModel
# from ..middlewares.rate_limiter import RateLimiter
class RateLimiter:
    def __init__(self, max_calls=None, period=None):
        pass
    async def check_limit(self, user_id, ip):
        return True  # Dummy implementation

# --- Hardcoded constants (from non-existent config file) ---
ENABLE_STT_ROUTE = os.getenv("ENABLE_STT_ROUTE", "True").lower() == "true"
MAX_STT_FILE_SIZE_MB = int(os.getenv("MAX_STT_FILE_SIZE_MB", 5))
STT_RATE_LIMIT = int(os.getenv("STT_RATE_LIMIT", 60))
TEMP_FILE_ENCRYPTION_KEY = os.getenv("TEMP_FILE_ENCRYPTION_KEY", os.urandom(32).hex()).encode()
WHISPER_MODEL_LOADED = os.getenv("WHISPER_MODEL_LOADED", "small.en")

# Security constants
MAX_CHUNK_SIZE = 1024 * 1024
AUDIO_HMAC_KEY = os.getenv("AUDIO_HMAC_KEY", os.urandom(32).hex()).encode()
INVALID_AUDIO_CHARS = re.compile(r'[\x00-\x1f\x7f-\x9f]')

_stt_killed = False

class AESCipher:
    def __init__(self):
        self.key = TEMP_FILE_ENCRYPTION_KEY
    
    def encrypt(self, raw: bytes) -> bytes:
        if _stt_killed:
            return raw
        try:
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            return nonce + encryptor.tag + encryptor.update(raw) + encryptor.finalize()
        except Exception as e:
            security_alert(f"Temp file encryption failed: {str(e)[:50]}")
            return raw

    def decrypt(self, encrypted: bytes) -> bytes:
        if _stt_killed or not encrypted or len(encrypted) < 28:
            return b''
        try:
            nonce, tag, ciphertext = encrypted[:12], encrypted[12:28], encrypted[28:]
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            security_alert(f"Temp file decryption failed: {str(e)[:50]}")
            return b''

_aes_cipher = AESCipher()
limiter = RateLimiter(max_calls=STT_RATE_LIMIT, period=60)

async def _hmac_audio_file(path: str) -> str:
    try:
        h = hmac.HMAC(AUDIO_HMAC_KEY, hashes.SHA384(), backend=default_backend())
        async with aiofiles.open(path, 'rb') as f:
            while chunk := await f.read(8192):
                h.update(chunk)
        return h.finalize().hex()
    except Exception as e:
        security_alert(f"HMAC generation failed: {str(e)[:50]}")
        return ""

async def _secure_tempfile(audio_data: bytes) -> str:
    if _stt_killed:
        return ""
    if len(audio_data) > MAX_STT_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Audio exceeds {MAX_STT_FILE_SIZE_MB}MB limit")
    
    temp_path = None
    try:
        encrypted_data = _aes_cipher.encrypt(audio_data)
        async with aiofiles.tempfile.NamedTemporaryFile(mode='wb', suffix='.enc', delete=False) as temp_file:
            await temp_file.write(encrypted_data)
            temp_path = temp_file.name
        return temp_path
    except Exception as e:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
        security_alert(f"Secure temp file failed: {str(e)[:50]}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Temp file creation failed")

async def _validate_stt_access(credentials: HTTPAuthorizationCredentials, ip: str) -> UserModel:
    if _stt_killed:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="STT service temporarily unavailable")
    if not ENABLE_STT_ROUTE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="STT service is currently disabled")

    user_id = credentials.credentials
    if not await validate_session_token(user_id):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid session token")

    if not await limiter.check_limit(user_id, ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="STT rate limit exceeded")

    return await UserModel.get_by_token(credentials.credentials)

router = APIRouter(prefix="/stt", dependencies=[Depends(HTTPBearer())], responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}})

@router.post("/upload")
async def upload_stt(file: UploadFile = File(...), credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()), request: Request = None) -> JSONResponse:
    if _stt_killed:
        return JSONResponse({"error": "STT service is down"}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

    try:
        user = await _validate_stt_access(credentials, request.client.host)
        raw_audio = await file.read()
        temp_path = await _secure_tempfile(raw_audio)
        audio_hash = await _hmac_audio_file(temp_path)

        start_time = datetime.utcnow()
        result = await transcribe_audio(temp_path)
        latency = (datetime.utcnow() - start_time).total_seconds()

        await log_stt_usage({"user_id": user.user_id, "audio_hash": audio_hash, "language": result["language"], "duration": result.get("duration", 0), "timestamp": start_time.isoformat(), "latency": latency})
        
        await asyncio.to_thread(os.unlink, temp_path)

        return JSONResponse({"text": result["text"], "clauses": result["clauses"], "language": result["language"], "latency": latency, "model": WHISPER_MODEL_LOADED})
    except HTTPException:
        raise
    except Exception as e:
        security_alert(f"STT processing failed: {str(e)[:50]}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="STT processing error")

@router.websocket("/realtime")
async def realtime_stt(websocket: WebSocket):
    if _stt_killed:
        await websocket.close(code=status.WS_1013_UNSUPPORTED)
        return
    await websocket.accept()
    try:
        auth_msg = await websocket.receive_json()
        session_token = auth_msg.get("token", "")
        user = await UserModel.get_by_token(session_token)
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        ip = websocket.client.host
        while True:
            chunk = await websocket.receive_bytes()
            if len(chunk) > MAX_CHUNK_SIZE:
                security_alert(f"Oversized chunk from {user.user_id}")
                continue
            if not await limiter.check_limit(user.user_id, ip):
                await websocket.send_json({"error": "Rate limit exceeded", "retry_after": 60})
                continue
            
            result = await transcribe_audio(chunk, stream=True)
            await websocket.send_json({"text": result["text"], "language": result["language"], "is_final": result.get("is_final", False), "timestamp": datetime.utcnow().isoformat()})
    except WebSocketDisconnect:
        log_event(f"WebSocket disconnected: {user.user_id if 'user' in locals() else 'unknown'}")
    except Exception as e:
        security_alert(f"WebSocket STT error: {str(e)[:50]}")
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)

@router.get("/status")
async def stt_status() -> JSONResponse:
    return JSONResponse({"status": "active" if WHISPER_MODEL_LOADED and not _stt_killed else "offline", "model": WHISPER_MODEL_LOADED[:3] + "..." if WHISPER_MODEL_LOADED else "none", "max_size_mb": MAX_STT_FILE_SIZE_MB, "rate_limit": STT_RATE_LIMIT, "enabled": bool(ENABLE_STT_ROUTE), "last_updated": datetime.utcnow().isoformat()})

def kill_stt():
    global _stt_killed
    _stt_killed = True
    log_event("STT: Engine killed.", level="critical")

stt_router = router
