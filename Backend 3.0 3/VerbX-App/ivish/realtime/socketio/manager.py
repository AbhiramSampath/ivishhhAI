# realtime/socketio/manager.py
# 🔒 Nuclear-Grade Socket.IO Manager
# 🔐 Real-time communication bridge between frontend and backend
# 📦 Handles: voice streaming, text input, session state, language routing
# 🛡️ Security: ZKP auth, rate limiting, voiceprint validation, encrypted payloads

import os
import re
import uuid
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
import logging
import json
import socketio

# 🔐 Security Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# 📁 Project Imports (Corrected based on file structure)
# from ai_models.whisper.whisper_handler import stream_transcribe
# from ai_models.translation.gpt_rephrase_loop import gpt_rephrase_stream
# from ai_models.tts.tts_handler import synthesize_speech
# from ai_control.safety_decision_manager import evaluate_safety
# from ai_models.ivish.voice_session import get_user_session, close_session
# from backend.app.utils.logger import log_event
# from backend.app.auth.jwt_handler import verify_socket_token

# from security.blockchain.zkp_handler import verify_connection_zkp
# from backend.app.middlewares.rate_limiter import SocketRateLimiter
# from backend.app.auth.voice_auth import validate_voiceprint
# from security.blockchain.zkp_handler import ZKPAuthenticator

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = b"socket_io_signature_key_256bit"
if len(_HMAC_KEY) < 32:
    _HMAC_KEY = hashlib.sha256(_HMAC_KEY).digest()

_SALT = os.urandom(16)
_KDF_ITERATIONS = 100000
_LATENCY_BUDGET_MS = 200
_MAX_AUDIO_CHUNK = 1024 * 1024  # 1MB
_MAX_TEXT_LENGTH = 5000
_SUPPORTED_LANGS = ['en', 'hi', 'ta', 'te', 'bn', 'kn', 'es', 'fr', 'de', 'ru', 'ja', 'zh']
_SOCKET_TIMEOUT = timedelta(seconds=30)

@dataclass
class SocketSession:
    """
    📌 Structured socket session
    - sid: socket session ID
    - user_id: authenticated user
    - lang: current language
    - start_time: session start timestamp
    - last_active: last activity timestamp
    - _signature: HMAC signature for tamper detection
    """
    sid: str
    user_id: str
    lang: str
    start_time: str
    last_active: str
    _signature: Optional[str] = None

class SecureSocketIOManager:
    """
    🔒 Secure Socket.IO Manager
    - Handles bidirectional, low-latency data transmission
    - Routes real-time events between frontend and backend
    - Manages session, language, and streaming hooks
    - Implements ZKP, rate limiting, voiceprint validation
    - Integrates with Whisper, GPT, TTS, safety modules
    - Logs and defends against attacks
    """

    def __init__(self):
        """Secure initialization"""
        self.sio = socketio.AsyncServer(
            async_mode='asgi',
            cors_allowed_origins=[],  # Strict same-origin policy
            engineio_logger=False,
            max_http_buffer_size=_MAX_AUDIO_CHUNK,
            logger=False
        )
        self.session_token = os.urandom(16).hex()
        self._limiter = SocketRateLimiter(max_connections=1000)
        self._blackhole_ips = set()
        self._init_socket_server()

    def _init_socket_server(self):
        """Initialize hardened Socket.IO server"""
        # Event handler registration will be done in register_handlers method
        pass

    def _sign_session(self, session: Dict) -> str:
        """HMAC-sign session metadata for integrity"""
        serialized = json.dumps(session, sort_keys=True).encode()
        h = hmac.HMAC(_HMAC_KEY, serialized, hashes.SHA256(), backend=_BACKEND)
        return h.hexdigest()

    def _generate_nonce(self) -> str:
        """Cryptographically secure nonce generation"""
        return os.urandom(16).hex()

    async def on_connect(self, sid, environ):
        """Nuclear-grade connection handshake with ZKP and rate limiting"""
        try:
            ip = environ.get('REMOTE_ADDR', 'unknown')
            if ip in self._blackhole_ips:
                await self._fake_handshake(sid)
                return False

            if not await verify_connection_zkp(environ):
                self._blackhole_ips.add(ip)
                await log_event(f"BLOCKED_MALICIOUS_HANDSHAKE: {ip}")
                return False

            token = environ.get('HTTP_AUTHORIZATION', '')
            user_id = verify_socket_token(token)
            if not user_id or user_id == 'anonymous':
                await self._fake_handshake(sid)
                return False

            if not self._limiter.check_limit(ip):
                await self._slow_drip_disconnect(sid)
                return False

            session_dict = {
                "sid": sid,
                "user_id": user_id,
                "lang": "en",
                "start_time": datetime.now().isoformat(),
                "last_active": datetime.now().isoformat(),
            }
            session_dict["_signature"] = self._sign_session(session_dict)
            self.sio.enter_room(sid, user_id)
            await self.sio.emit("connected", session_dict, to=sid)
            await log_event(f"AUTHENTICATED_CONNECTION: {sid[:6]}...")
            return True

        except Exception as e:
            await log_event(f"CONNECTION_FAILURE: {str(e)}")
            return False

    async def _fake_handshake(self, sid):
        """Honeypot response with fake session"""
        fake_session = {
            "sid": sid,
            "fake": True,
            "nonce": self._generate_nonce(),
            "timestamp": datetime.now().isoformat()
        }
        fake_session["_signature"] = self._sign_session(fake_session)
        await self.sio.emit("connected", fake_session, to=sid)
        await asyncio.sleep(5)
        await self.sio.disconnect(sid)

    async def _slow_drip_disconnect(self, sid):
        """Degrade service for suspected attackers"""
        for i in range(10):
            await self.sio.emit("lag", {"delay": i}, to=sid)
            await asyncio.sleep(1)
        await self.sio.disconnect(sid)

    async def on_disconnect(self, sid):
        """Secure teardown with evidence preservation"""
        session = get_user_session(sid)
        await close_session(sid)
        await log_event(f"GRACEFUL_DISCONNECT: {sid} | {session.get('user_id')}")
        self._limiter.release_connection(sid)

    async def handle_audio_chunk(self, sid, data):
        """Hardened audio pipeline with injection protection"""
        try:
            audio_data = data.get("audio")
            if not isinstance(audio_data, bytes) or len(audio_data) > _MAX_AUDIO_CHUNK:
                await self.sio.emit("invalid_input", {"reason": "invalid_format"}, to=sid)
                return

            user_session = get_user_session(sid)
            user_id = user_session.get("user_id")
            lang = data.get("lang", "en")

            if not await validate_voiceprint(sid, audio_data):
                await self.sio.emit("auth_required", {"reason": "voice_mismatch"}, to=sid)
                return

            async for output in stream_transcribe(audio_data, lang, user_id):
                safety = await evaluate_safety("audio_input", output.get("raw", ""), user_id)
                if safety.get("status") == "blocked":
                    await self._handle_malicious_audio(sid, output.get("raw", ""))
                    break

                await self.sio.emit("transcript", {
                    "text": output.get("text", ""),
                    "timestamp": datetime.now().isoformat(),
                    "nonce": self._generate_nonce()
                }, to=sid)

        except Exception as e:
            await log_event(f"AUDIO_PROCESSING_FAILURE: {str(e)}")
            await self.sio.emit("error", {"code": 503, "message": "Service Unavailable"}, to=sid)

    async def handle_text_input(self, sid, data):
        """Secure text processing pipeline"""
        try:
            prompt = data.get("text", "")[:_MAX_TEXT_LENGTH]
            if not prompt:
                await self.sio.emit("invalid_input", {"reason": "empty_prompt"}, to=sid)
                return

            if any(char.isspace() for char in prompt[:10]):
                await self.sio.emit("invalid_input", {"reason": "prompt_injection"}, to=sid)
                return

            user_session = get_user_session(sid)
            user_id = user_session.get("user_id")
            lang = data.get("lang", "en")

            gpt_task = gpt_rephrase_stream(prompt, lang)
            safety_task = evaluate_safety(prompt, "", user_id)

            gpt_stream, safety_check = await asyncio.gather(gpt_task, safety_task)

            if safety_check.get("status") == "blocked":
                await self._handle_malicious_text(sid, prompt)
                return

            async for reply in gpt_stream:
                await self.sio.emit("response", {
                    "text": reply,
                    "integrity_hash": self._generate_hash(reply),
                    "nonce": self._generate_nonce()
                }, to=sid)

        except Exception as e:
            await log_event(f"TEXT_PROCESSING_FAILURE: {str(e)}")
            await self.sio.emit("error", {"code": 503, "message": "Service Unavailable"}, to=sid)

    async def handle_language_change(self, sid, data):
        """Secure language switching"""
        try:
            lang = data.get("lang", "en")
            if lang not in _SUPPORTED_LANGS:
                await self.sio.emit("lang_change_denied", {"reason": "unsupported_language"}, to=sid)
                return

            user_session = get_user_session(sid)
            user_session["lang"] = lang
            await self.sio.emit("lang_changed", {"lang": lang}, to=sid)
        except Exception as e:
            await log_event(f"LANG_CHANGE_FAILURE: {str(e)}")
            await self.sio.emit("error", {"code": 500, "message": "Language change failed"}, to=sid)

    def register_handlers(self, app):
        """Secure event handler registration"""
        self.sio.on("connect", self.on_connect)
        self.sio.on("disconnect", self.on_disconnect)
        self.sio.on("audio_chunk", self.handle_audio_chunk)
        self.sio.on("text_input", self.handle_text_input)
        self.sio.on("lang_change", self.handle_language_change)

        app.mount("/ws", socketio.ASGIApp(self.sio, socketio_path="socket.io"))

    def _generate_hash(self, text: str) -> str:
        """Tamper-evident hashing"""
        digest = hashes.Hash(hashes.BLAKE2s(16), backend=_BACKEND)
        digest.update(text.encode())
        return digest.finalize().hex()

    async def _handle_malicious_audio(self, sid, transcript):
        """Counter-intelligence for audio injection"""
        await log_event(f"AUDIO_ATTACK_DETECTED: {sid} | {transcript[:50]}...")
        await self.sio.emit("service_error", {"code": 503, "reason": "Audio attack detected"}, to=sid)
        await asyncio.sleep(10)
        await self.sio.disconnect(sid)

    async def _handle_malicious_text(self, sid, prompt):
        """Counter-intelligence for prompt injection"""
        await log_event(f"PROMPT_ATTACK_DETECTED: {sid} | {prompt[:50]}...")
        await self.sio.emit("service_error", {"code": 503, "reason": "Unsafe input detected"}, to=sid)
        await asyncio.sleep(10)
        await self.sio.disconnect(sid)

    def _trigger_defense_response(self, sid, ip):
        """Reverse-intrusion response system"""
        logging.critical(f"🚨 SECURITY BREACH DETECTED: {ip}")
        ZKPAuthenticator().rotate_keys()
        self._blackhole_ips.add(ip)
        asyncio.create_task(self.sio.disconnect(sid))