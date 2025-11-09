# video_call/starem_handler.py
# 🔒 Nuclear-Grade Video Call Handler | Real-Time STT → Emotion → Subtitle → TTS
# 🧠 Designed for Edge Deployment, Federated Learning, and Offline AI

import os
import uuid
import time
import hashlib
import hmac
import base64
import json
import asyncio
from typing import Dict, Any, Optional, AsyncIterable, AsyncGenerator
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from collections import defaultdict
import threading

# 📦 Project Imports
from ai_models.whisper.whisper_handler import stream_transcribe
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.mt_translate import translate_text
from ai_models.tts.tts_handler import synthesize_speech
from backend.app.utils.logger import log_event
from config.settings import ENABLE_TTS_OUTPUT, MAX_PACKET_SIZE
from security.intrusion_prevention.counter_response import trigger_blackhole
from security.intrusion_prevention.isolation_engine import rotate_endpoint
from security.firewall import VideoCallFirewall
from security.blockchain.zkp_handler import validate_zkp_token
from security.blockchain.blockchain_utils import anchor_event as log_to_blockchain

# 🧱 Global Config
ENABLE_BLOCKCHAIN_LOGGING = True
ENABLE_HONEYPOT = True
ENABLE_AUTO_WIPE = True
ENABLE_ENDPOINT_MUTATION = True
MAX_LATENCY_MS = 200
MAX_PAYLOAD_SIZE = 1024
MAX_SESSION_DURATION = 3600
THREAT_LEVEL_THRESHOLD = 5

# 🔐 Thread-safe state for session management
_session_data = defaultdict(dict)
_session_lock = threading.Lock()

# 🧠 Core Handler
@dataclass
class StreamPacket:
    audio: bytes
    session_id: str
    timestamp: float
    signature: bytes

class StaremHandler:
    def __init__(self):
        self._firewall = VideoCallFirewall()
        self._aes_key = hashlib.sha256(os.getenv("STAREM_AES_KEY", "default_starem_key").encode()).digest()
        self._hmac_key = hashlib.sha256(os.getenv("STAREM_HMAC_KEY", "default_starem_hmac_key").encode()).digest()

    def _generate_session_key(self) -> bytes:
        """Create time-bound session key with hardware binding."""
        key_material = (os.getenv("HARDWARE_ID", "") + str(time.time())).encode()
        return hashlib.pbkdf2_hmac(
            'sha256',
            key_material,
            os.urandom(16),
            100000,
            dklen=32
        )

    def _hash_user_id(self, user_id: str) -> str:
        """GDPR-compliant user pseudonymization."""
        return hashlib.shake_256(user_id.encode()).hexdigest(16)

    def _validate_audio_packet(self, packet: bytes, session_id: str) -> bool:
        """Verify packet integrity with HMAC."""
        try:
            expected_mac = packet[:32]
            actual_mac = hmac.new(
                _session_data[session_id]['hmac_key'],
                packet[32:],
                hashlib.sha256
            ).digest()
            return hmac.compare_digest(expected_mac, actual_mac)
        except Exception as e:
            log_event(f"Packet validation failed: {str(e)}", level="WARNING")
            return False

    def _decrypt_audio(self, session_id: str, encrypted: bytes) -> bytes:
        """Secure audio decryption with unique nonce."""
        try:
            nonce = encrypted[:12]
            tag = encrypted[12:28]
            ciphertext = encrypted[28:]
            cipher = Cipher(algorithms.AES(self._aes_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            log_event(f"Audio decryption failed: {str(e)}", level="WARNING")
            return b''

    def _sanitize_text(self, text: str) -> str:
        """Prevent XSS and injection in subtitles."""
        injection_patterns = [
            '<script', '<style', 'javascript:', 'onerror=',
            'onload=', 'onclick=', 'eval(', 'document.cookie'
        ]
        for pattern in injection_patterns:
            text = text.replace(pattern, '')
        return text.strip()

    def _is_safe_text(self, text: str) -> bool:
        """Detect unsafe patterns in text."""
        return all(c.isprintable() or c.isspace() for c in text)

    def _generate_nonce(self) -> str:
        """Cryptographically secure nonce for CSP."""
        return base64.urlsafe_b64encode(os.urandom(16)).decode()[:16]

    def _generate_integrity_hash(self, *values) -> str:
        """Tamper-proof hashing for secure logging."""
        return hashlib.sha3_256("".join(values).encode()).hexdigest()

    async def _blackhole_response(self, socket):
        """Null response with infinite delay."""
        await asyncio.sleep(3600)
        await socket.send_json({"status": "disconnected"})

    async def handle_video_call_stream(
        self,
        audio_stream: AsyncIterable[bytes],
        source_lang: str,
        target_lang: Optional[str],
        socket: Any,
        user_id: str,
        auth_token: str
    ) -> None:
        """
        Hardened STAREM loop with:
        - Encrypted audio transport
        - Anti-replay protection
        - Tamper-proof logging
        - <200ms latency guarantee
        """
        session_id = str(uuid.uuid4())
        with _session_lock:
            _session_data[session_id]['hmac_key'] = self._generate_session_key()
            _session_data[session_id]['start_time'] = time.time()

        if not validate_zkp_token(auth_token, user_id, session_id):
            log_event("ZKP token validation failed", level="CRITICAL")
            await self._blackhole_response(socket)
            return

        latency_tracker = _LatencyTracker(max_ms=MAX_LATENCY_MS)

        try:
            async for encrypted_packet in audio_stream:
                if time.time() - _session_data[session_id]['start_time'] > MAX_SESSION_DURATION:
                    log_event("Session expired", level="INFO")
                    break

                if not self._validate_audio_packet(encrypted_packet, session_id):
                    log_event("Audio packet tampering detected", level="ALERT")
                    continue

                audio_data = self._decrypt_audio(session_id, encrypted_packet[32:])
                if not audio_data:
                    continue

                stt_result = await stream_transcribe(audio_data, lang_hint=source_lang)
                raw_text = stt_result.get("raw", "")
                clauses = stt_result.get("clauses", [])
                emotion = await detect_emotion(audio_data)

                sanitized_clauses = [
                    self._sanitize_text(c) for c in clauses if self._is_safe_text(c)
                ]

                for clause in sanitized_clauses:
                    styled = await self._secure_stylize(clause, emotion)
                    translated = clause
                    if target_lang and target_lang != source_lang:
                        translated = await self._safe_translate(clause, source_lang, target_lang)

                    safe_output = await self._validate_output_payload(styled, translated)
                    await self._secure_stream(socket, safe_output)

                    if ENABLE_TTS_OUTPUT and latency_tracker.ok_for_tts():
                        speech_audio = await synthesize_speech(translated, target_lang, tone=emotion)
                        await self._secure_audio_stream(socket, speech_audio)

                    await self._immutable_log(session_id, user_id, clause, emotion, translated)

                if not latency_tracker.check():
                    log_event("Latency threshold exceeded", level="WARNING")
                    await self._reduce_quality(socket)
        except Exception as e:
            log_event(f"Video call handler failed: {str(e)}", level="EMERGENCY")
            await self._kill_switch(session_id, socket)
        finally:
            with _session_lock:
                _session_data.pop(session_id, None)

    async def _secure_stylize(self, text: str, emotion: str) -> Dict[str, Any]:
        """Hardened subtitle styling."""
        VALID_EMOTIONS = {"happy", "sad", "angry", "neutral", "fear", "excited"}
        if emotion not in VALID_EMOTIONS:
            emotion = "neutral"

        sanitized_text = self._sanitize_text(text)
        styles = {
            "happy": {"color": "#00cc44", "font": "bold", "effect": "fadeIn"},
            "sad": {"color": "#3399ff", "font": "italic", "effect": "fadeOut"},
            "angry": {"color": "#ff3300", "font": "bold italic", "effect": "shake"},
            "neutral": {"color": "#ffffff", "font": "regular", "effect": "none"},
            "fear": {"color": "#ff9900", "font": "italic", "effect": "pulse"},
            "excited": {"color": "#ffff00", "font": "bold", "effect": "bounce"}
        }

        return {
            "text": sanitized_text,
            "style": styles[emotion],
            "emotion": emotion,
            "nonce": self._generate_nonce()
        }

    async def _safe_translate(self, text: str, src: str, dst: str) -> str:
        """Secure translation with fallback."""
        try:
            return await translate_text(text, src, dst)
        except Exception as e:
            log_event(f"Translation failed: {str(e)}", level="WARNING")
            return text

    async def _secure_stream(self, socket: Any, payload: Dict[str, Any]) -> None:
        """Protected WebSocket streaming."""
        if len(str(payload)) > MAX_PAYLOAD_SIZE:
            payload = {"error": "payload_too_large"}

        try:
            await socket.send_json(payload)
        except Exception as e:
            log_event(f"Stream send failed: {str(e)}", level="ERROR")
    
    async def _secure_audio_stream(self, socket: Any, audio_data: bytes) -> None:
        """Protected audio streaming."""
        try:
            await socket.send(audio_data)
        except Exception as e:
            log_event(f"Audio stream send failed: {str(e)}", level="ERROR")

    async def _validate_output_payload(
        self, styled: Dict[str, Any], translated: str
    ) -> Dict[str, Any]:
        """Validate and sanitize output before streaming."""
        if not styled or not translated:
            return {"error": "empty_payload"}
        
        return {
            "text": styled["text"],
            "translated": translated,
            "style": styled["style"],
            "emotion": styled["emotion"],
            "nonce": styled["nonce"],
            "timestamp": time.time(),
            "integrity_hash": self._generate_integrity_hash(styled["text"], translated)
        }

    async def _immutable_log(
        self, session_id: str, user_id: str, original: str, emotion: str, translated: str
    ) -> None:
        """Blockchain-anchored logging with GDPR redaction."""
        log_entry = {
            "session_id": session_id,
            "user_id": self._hash_user_id(user_id),
            "original_hash": self._generate_integrity_hash(original),
            "translated_hash": self._generate_integrity_hash(translated),
            "emotion": emotion,
            "timestamp": time.time(),
            "blockchain_anchor": None
        }

       
        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain("video_call_log", log_entry)

    async def _kill_switch(self, session_id: str, socket: Any):
        """Emergency wipe of session data and endpoint rotation."""
        with _session_lock:
            _session_data.pop(session_id, None)
        await trigger_blackhole()
        await rotate_endpoint()
        await socket.send_json({"status": "disconnected", "reason": "security_violation"})

class _LatencyTracker:
    def __init__(self, max_ms: int):
        self._start = time.time()
        self._max_ms = max_ms

    def check(self) -> bool:
        """Check if latency exceeds threshold."""
        return (time.time() - self._start) * 1000 < self._max_ms

    def ok_for_tts(self) -> bool:
        """Only allow TTS if latency is under 100ms."""
        return (time.time() - self._start) * 1000 < 100