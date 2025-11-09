# backend/routes/video_call.py

import asyncio
import os
import time
import uuid
import hashlib
import hmac
import logging
import json
from typing import Dict, List, Optional, Any, Union
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from starlette.status import WS_1008_POLICY_VIOLATION, WS_1009_MESSAGE_TOO_BIG
from cryptography.hazmat.primitives import constant_time

# Project Imports - CORRECTED PATHS
from voice_call.translator import handle_bilingual_call
from ai_models.whisper.whisper_handler import stream_transcribe
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.tts.tts_handler import synthesize_speech
from ai_models.translation.mt_translate import translate_text
from utils.logger import log_event
from security.firewall import Firewall
from security.blockchain.zkp_handler import ZeroKnowledgeProof
from ai_models.ivish.memory_agent import MemorySessionHandler
from ..auth.jwt_handler import get_user_id_from_token
from backend.app.services.ivish_service import end_session as end_ivish_session
from middlewares.rate_limiter import RateLimiter
from security.intrusion_prevention.counter_response import BlackholeRouter

# Initialize secure components
logger = logging.getLogger(__name__)
memory_handler = MemorySessionHandler()
backend = default_backend()
rate_limiter = RateLimiter()
blackhole_router = BlackholeRouter()

# Constants
_DEFAULT_KDF_SALT = os.getenv("CALL_KDF_SALT", "default_call_salt").encode()
_SESSION_SALT = os.getenv("SESSION_SALT", "default_session_salt").encode()
_CALL_TIMEOUT_SEC = int(os.getenv("CALL_TIMEOUT_SEC", 3600))
_AUDIO_CHUNK_SIZE = int(os.getenv("AUDIO_CHUNK_SIZE", 4096))
_MAX_SESSIONS_PER_USER = int(os.getenv("MAX_SESSIONS_PER_USER", 3))
_MAX_SUBTITLE_LENGTH = int(os.getenv("MAX_SUBTITLE_LENGTH", 200))
_ENCRYPTION_KEY = os.getenv("CALL_ENCRYPTION_KEY", "default_encryption_key_32bytes").encode()
_HMAC_KEY = os.getenv("CALL_HMAC_KEY", "default_hmac_key").encode()
_DEFAULT_IV_SIZE = 12

class CallSession:
    def __init__(self, user_id: str, session_id: str):
        self.user_id = user_id
        self.session_id = session_id
        self.start_time = time.time()
        self.last_activity = time.time()
        self.session_key = self._derive_key(user_id, session_id)
        self._active = True
        self.hmac_context = hmac.HMAC(self.session_key, b'', hashes.SHA256(), backend=backend)

    def _derive_key(self, user_id: str, session_id: str) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=_SESSION_SALT, info=b'video_call', backend=backend)
        return hkdf.derive(f"{user_id}:{session_id}".encode())

    def encrypt_audio(self, audio: bytes) -> bytes:
        nonce = os.urandom(_DEFAULT_IV_SIZE)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(nonce), backend=backend)
        encryptor = cipher.encryptor()
        return nonce + encryptor.update(audio) + encryptor.finalize()

    def decrypt_audio(self, encrypted: bytes) -> bytes:
        if len(encrypted) < 28:
            raise ValueError("Invalid encrypted data")
        nonce = encrypted[:_DEFAULT_IV_SIZE]
        tag = encrypted[_DEFAULT_IV_SIZE:28]
        ciphertext = encrypted[28:]
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def update_hmac(self, data: bytes) -> None:
        self.hmac_context.update(data)

    def verify_hmac(self, signature: bytes) -> bool:
        expected = self.hmac_context.finalize()
        return constant_time.compare_digest(expected, signature)

    def is_active(self) -> bool:
        return self._active and (time.time() - self.start_time < _CALL_TIMEOUT_SEC)

    def terminate(self) -> None:
        self._active = False
        log_event(f"CALL: Session {self.session_id} terminated", secure=True)

class CallSessionManager:
    def __init__(self):
        self.sessions = {}
        self.session_count = {}
    
    def generate_session_id(self, user_id: str) -> str:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=_DEFAULT_KDF_SALT, info=b'video_call', backend=backend)
        return hkdf.derive(user_id.encode() + os.urandom(16)).hex()

    def can_start_session(self, user_id: str) -> bool:
        return self.session_count.get(user_id, 0) < _MAX_SESSIONS_PER_USER

    async def end_session(self, user_id: str):
        if user_id in self.sessions:
            session = self.sessions.pop(user_id)
            session.terminate()
            self.session_count[user_id] = max(0, self.session_count.get(user_id, 0) - 1)
            log_event(f"CALL: Session {session.session_id} for {user_id} ended", secure=True)

class VideoCallRouter:
    def __init__(self):
        self.router = APIRouter()
        self._session_manager = CallSessionManager()
        self._firewall = Firewall()

    @property
    def router(self):
        return self._router

    async def websocket_call_handler(
        self,
        websocket: WebSocket,
        token: str,
        session_id: Optional[str] = None
    ):
        await websocket.accept()
        user_id = await get_user_id_from_token(token)

        if not await self._firewall.verify_voice_token(token, user_id):
            await websocket.close(code=WS_1008_POLICY_VIOLATION)
            return

        if not self._session_manager.can_start_session(user_id):
            await websocket.close(code=WS_1008_POLICY_VIOLATION, reason="Too many active sessions")
            return

        session_id = self._session_manager.generate_session_id(user_id)
        session = CallSession(user_id, session_id)
        self._session_manager.sessions[user_id] = session
        log_event(f"CALL: Session {session_id} for {user_id} started")

        try:
            while session.is_active():
                audio_chunk = await websocket.receive_bytes()
                if len(audio_chunk) > _AUDIO_CHUNK_SIZE:
                    log_event(f"CALL: Oversized chunk from {user_id}", level="WARNING")
                    await websocket.close(code=WS_1009_MESSAGE_TOO_BIG)
                    break
                
                result = await self._process_call_chunk(audio_chunk, session)
                if not result:
                    continue

                await websocket.send_json({
                    "subtitle": result["text"][:_MAX_SUBTITLE_LENGTH],
                    "emotion": result["emotion"],
                    "latency": f"{result['latency_ms']:.1f}ms",
                    "session": session_id[-8:]
                })
        except WebSocketDisconnect:
            log_event(f"CALL: {user_id} disconnected", secure=True)
        except Exception as e:
            log_event(f"CALL: Error in {session_id} - {str(e)}", level="ERROR")
            await blackhole_router.trigger()
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        finally:
            await self._session_manager.end_session(user_id)

    async def _process_call_chunk(self, audio_chunk: bytes, session: CallSession) -> Optional[Dict[str, Any]]:
        try:
            decrypted = session.decrypt_audio(audio_chunk)
            stt_task = asyncio.create_task(stream_transcribe(decrypted))
            stt_result = await stt_task
            
            emotion = await detect_emotion(stt_result["text"])
            translated = await translate_text(stt_result["text"], src="auto", tgt="en")
            
            return {"text": translated, "emotion": emotion, "latency_ms": (time.time() - session.start_time) * 1000}
        except Exception as e:
            log_event(f"CALL: Chunk processing failed - {str(e)}", level="ERROR")
            return None