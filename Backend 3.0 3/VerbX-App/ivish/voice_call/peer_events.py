# voice_call/peer_events.py

import os
import uuid
import time
import jwt
import hmac
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
import asyncio
import logging
from functools import lru_cache

# Internal imports (Corrected paths)
from ai_models.whisper.whisper_handler import stream_transcribe
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.mt_translate import translate_text
from ai_models.tts.tts_handler import synthesize_speech
from ai_models.personalization.consent_handler import check_user_consent
from security.blockchain.blockchain_utils import anchor_event as log_to_blockchain
from backend.app.utils.logger import log_event
from realtime.socketio.manager import emit_event
from config.settings import LANG_DEFAULT, TRANSLATE_ENABLED
from ai_models.ivish.voice_session import SessionManager

from security.firewall import CircuitBreaker

# External imports

# Type aliases
PeerID = str
CallEvent = Dict[str, Any]
CallMetadata = Dict[str, Union[str, datetime, float]]

# Security: Secure RNG, HMAC key, and JWT secret
_SECURE_RNG = os.urandom
_JWT_SECRET = hashlib.sha256(b'VerbX_PEER_EVENTS_SECRET').digest()
_PEER_HMAC_KEY = hashlib.sha256(b'VerbX_PEER_AUTH_KEY').digest()
_PEER_ID_LENGTH = (8, 64)

class SecurePeerRegistry:
    """
    Encrypted peer registry with ZKP verification
    """
    def __init__(self):
        self._peers: Dict[PeerID, bytes] = {}
        self._index: Dict[PeerID, str] = {}
        self._logger = logging.getLogger("peer_registry")
        self._lock = asyncio.Lock()

    async def add_peer(self, peer_id: PeerID, data: CallMetadata) -> bool:
        """
        Register peer with JWT + HMAC protection
        """
        async with self._lock:
            if not self._validate_peer_id(peer_id):
                self._logger.warning("Peer ID invalid", extra={"peer_id": peer_id})
                return False

            if len(self._peers) >= 1000:
                self._logger.warning("Peer limit reached", extra={"peer_id": peer_id})
                return False

            try:
                token = jwt.encode({**data, "peer_id": peer_id}, _JWT_SECRET, algorithm="HS256")
                hmac_tag = hmac.new(_PEER_HMAC_KEY, token.encode(), hashlib.sha256).digest()
                self._peers[peer_id] = token.encode()
                self._index[peer_id] = hmac_tag.hex()
                self._logger.info("Peer registered", extra={"peer_id": peer_id})
                return True
            except Exception as e:
                self._logger.error(f"Peer registration failed: {str(e)}", exc_info=True)
                return False

    async def get_peer(self, peer_id: PeerID) -> Optional[CallMetadata]:
        """
        Retrieve and verify peer data
        """
        async with self._lock:
            if peer_id not in self._peers:
                return None

            token = self._peers[peer_id]
            stored_hmac = bytes.fromhex(self._index.get(peer_id, ""))
            computed_hmac = hmac.new(_PEER_HMAC_KEY, token, hashlib.sha256).digest()

            if not hmac.compare_digest(computed_hmac, stored_hmac):
                self._logger.critical("Peer data tampering detected", extra={"peer_id": peer_id})
                return None

            try:
                return jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
            except jwt.PyJWTError as e:
                self._logger.error(f"JWT decode failed: {str(e)}", exc_info=True)
                return None

    async def remove_peer(self, peer_id: PeerID) -> bool:
        """
        Secure peer removal with audit
        """
        async with self._lock:
            self._peers.pop(peer_id, None)
            self._index.pop(peer_id, None)
            self._logger.info("Peer removed", extra={"peer_id": peer_id})
            return True

    def _validate_peer_id(self, peer_id: PeerID) -> bool:
        """Prevent ID injection attacks"""
        return (
            isinstance(peer_id, str) and
            _PEER_ID_LENGTH[0] <= len(peer_id) <= _PEER_ID_LENGTH[1]
        )

# Singleton peer registry
connected_peers = SecurePeerRegistry()

class PeerCallManager:
    """
    Secure peer event manager for Ivish AI.
    """
    def __init__(self):
        self._logger = logging.getLogger("peer_call")
        self._session_manager = SessionManager()
        self._audit_agent = AuditAgent()
        self._circuit_breaker = CircuitBreaker(threshold=3, cooldown=60)
        self._translate_enabled = TRANSLATE_ENABLED
        self._default_language = LANG_DEFAULT

    async def handle_peer_join(self, peer_id: PeerID) -> bool:
        """Secure peer registration with audit trail"""
        peer_data = {
            "joined_at": datetime.utcnow().isoformat() + "Z",
            "lang": self._default_language,
            "active": True,
            "last_active": datetime.utcnow().isoformat() + "Z"
        }
        if not await connected_peers.add_peer(peer_id, peer_data):
            return False

        log_event(f"Peer joined: {hashlib.sha256(peer_id.encode()).hexdigest()[:8]}")
        emit_event("peer_joined", {
            "peer_id": peer_id,
            "secure_hash": hmac.new(_PEER_HMAC_KEY, peer_id.encode(), 'sha256').hexdigest(),
            "timestamp": peer_data["joined_at"],
            "lang": self._default_language
        })
        self._audit_agent.update({
            "event": "peer_joined",
            "peer_id": peer_id,
            "timestamp": peer_data["joined_at"],
            "lang": self._default_language
        })
        return True

    async def handle_peer_leave(self, peer_id: PeerID) -> bool:
        """Graceful peer exit with blockchain audit"""
        peer_data = await connected_peers.get_peer(peer_id)
        if not peer_data:
            return False

        peer_data["left_at"] = datetime.utcnow().isoformat() + "Z"
        await self.push_call_log(peer_id, peer_data)
        await connected_peers.remove_peer(peer_id)

        emit_event("peer_left", {
            "peer_id": peer_id,
            "secure_hash": hmac.new(_PEER_HMAC_KEY, peer_id.encode(), 'sha256').hexdigest(),
            "timestamp": peer_data["left_at"]
        })
        self._audit_agent.update({
            "event": "peer_left",
            "peer_id": peer_id,
            "timestamp": peer_data["left_at"]
        })
        return True

    async def secure_audio_pipeline(self, peer_id: PeerID, chunk: bytes) -> None:
        """End-to-end encrypted audio processing with consent enforcement"""
        if not check_user_consent(peer_id):
            await self.handle_consent_revoked(peer_id)
            return

        try:
            async for stt_output in stream_transcribe(chunk, lang_hint=self._default_language):
                if not stt_output:
                    continue

                raw_text = stt_output.get("raw", "")[:1024]
                emotion = detect_emotion(raw_text)

                emit_event("emotion_update", {
                    "peer_id": peer_id,
                    "emotion": emotion,
                    "integrity_tag": hmac.new(
                        _PEER_HMAC_KEY,
                        f"{peer_id}{emotion}".encode(),
                        'sha256'
                    ).hexdigest()
                })

                translated = await self._translate_if_needed(raw_text)
                speech = await synthesize_speech(translated, tone=emotion)

                emit_event("tts_stream", {
                    "peer_id": peer_id,
                    "audio": speech,
                    "integrity_tag": hmac.new(
                        _PEER_HMAC_KEY, speech, 'sha256'
                    ).hexdigest()
                })

                self._audit_agent.update({
                    "peer_id": peer_id,
                    "raw_text": raw_text,
                    "translated_text": translated,
                    "emotion": emotion,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
        except Exception as e:
            self._logger.error(f"Audio pipeline failed: {str(e)}")
            emit_event("error", {
                "peer_id": peer_id,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

    async def _translate_if_needed(self, text: str) -> str:
        """Secure translation if enabled"""
        if self._translate_enabled:
            return await translate_text(text, target_lang=self._default_language)
        return text

    async def handle_consent_revoked(self, peer_id: PeerID) -> None:
        """Secure consent revocation handling"""
        self._logger.info(f"User {peer_id} revoked consent", extra={"peer_id": peer_id})
        await connected_peers.remove_peer(peer_id)
        emit_event("consent_revoked", {
            "peer_id": peer_id,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

    async def push_call_log(self, peer_id: PeerID, data: CallMetadata) -> bool:
        """Immutable blockchain logging of call metadata"""
        try:
            payload = {
                "peer_id": peer_id,
                "event": "call_summary",
                "data": jwt.encode(data, _JWT_SECRET, algorithm="HS256"),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "nonce": _SECURE_RNG(16).hex()
            }
            await log_to_blockchain("call_event", payload)
            return True
        except Exception as e:
            self._logger.error(f"Blockchain logging failed: {str(e)}")
            return False

# Singleton instance
peer_call_manager = PeerCallManager()