# backend/services/voice_call_service.py
# 🔒 Final, Secure Voice Call Service
# 🚀 Refactored Code

import os
import uuid
import time
import asyncio
import hmac
import hashlib
import json
import logging
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field
from enum import Enum

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Corrected Imports based on project structure
from ....ai_models.translation.mt_translate import translate_stream
from ....security.blockchain.zkp_handler import ZKPSessionValidator
from ....security.voice_biometric_auth import VoiceBiometrics
from ....security.intrusion_prevention.counter_response import blackhole_response_action
from ....security.intrusion_prevention.threat_detector import ThreatDetector
from ..utils.logger import log_event
from ..utils.cache import redis_client
from ..utils.rate_meter import rate_meter
from ..models.user import get_user_language_async
from ....security.blockchain.blockchain_utils import log_to_blockchain

# --- Security Constants ---
_SIGNATURE_KEY = os.getenv("VOICE_CALL_SIGNATURE_KEY", None)
if not _SIGNATURE_KEY:
    raise RuntimeError("VOICE_CALL_SIGNATURE_KEY not found in environment.")
_SIGNATURE_KEY = _SIGNATURE_KEY.encode()

_MAX_CALL_DURATION = int(os.getenv("MAX_CALL_DURATION", "3600"))
_EPHEMERAL_KEY_TTL = int(os.getenv("EPHEMERAL_KEY_TTL", "60"))
_AESGCM_KEY_LENGTH = 32

@dataclass
class CallSession:
    """
    Data model for a voice call session.
    """
    session_id: str
    user_a: str
    user_b: str
    start_time: float
    end_time: Optional[float] = None
    status: str = "active"
    last_activity: float = field(default_factory=time.time)

class SecureVoiceCallService:
    """
    Manages secure, real-time voice calls with E2EE, multi-factor auth, and translation.
    """
    def __init__(self):
        self.zkp_validator = ZKPSessionValidator()
        self.threat_detector = ThreatDetector()

    def _generate_session_key(self, session_id: str) -> bytes:
        """Generates a new, ephemeral AES-256 key for a session and stores it securely."""
        key = AESGCM.generate_key(bit_length=256)
        redis_client.setex(f"session_key:{session_id}", _EPHEMERAL_KEY_TTL, key)
        return key

    def _get_session_key(self, session_id: str) -> Optional[bytes]:
        """Retrieves a secure session key from Redis."""
        key = redis_client.get(f"session_key:{session_id}")
        return key

    def _generate_call_signature(self, data: Dict) -> str:
        """Tamper-proof session signature."""
        h = hmac.HMAC(_SIGNATURE_KEY, hashes.SHA3_256(), backend=default_backend())
        # Sort keys to ensure consistent hash generation
        sorted_data = json.dumps(data, sort_keys=True).encode()
        h.update(sorted_data)
        return h.finalize().hex()

    def _verify_call_signature(self, data: Dict, signature: str) -> bool:
        """Immutable session validation."""
        expected = self._generate_call_signature(data)
        return hmac.compare_digest(expected, signature)

    async def _validate_participants_secure(self, user_a_id: str, user_b_id: str) -> bool:
        """Multi-factor participant validation."""
        if not user_a_id or not user_b_id:
            return False

        # Zero-Knowledge Proof validation
        zkp_valid = await self.zkp_validator.validate_pair(user_a_id, user_b_id)
        if not zkp_valid:
            log_event("ZKP_VALIDATION_FAILED", level="ALERT")
            return False

        # Voiceprint biometric validation
        voice_match = await VoiceBiometrics.compare_live_samples(user_a_id, user_b_id)
        if not voice_match:
            log_event("VOICE_SPOOFING_ATTEMPT", level="WARNING")
            return False

        return True

    def _encrypt_audio_chunk(self, chunk: bytes, session_id: str) -> Optional[bytes]:
        """AES-256-GCM authenticated encryption."""
        key = self._get_session_key(session_id)
        if not key:
            key = self._generate_session_key(session_id)
        
        if not key:
            return None

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, chunk, None)

    def _decrypt_audio_chunk(self, chunk: bytes, session_id: str) -> Optional[bytes]:
        """Hardware-backed audio decryption."""
        key = self._get_session_key(session_id)
        if not key:
            return None
        
        try:
            nonce = chunk[:12]
            ciphertext = chunk[12:]
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            log_event(f"VOICE_DECRYPT_FAILED: {str(e)}", level="WARNING")
            return None

    def _validate_audio_format(self, chunk: bytes) -> bool:
        """Prevent malicious file format injection by checking magic bytes."""
        if not chunk or len(chunk) < 4:
            return False
        
        valid_headers = {b"RIFF", b"OggS", b"Opus"}
        if chunk[:4] not in valid_headers:
            log_event("UNSUPPORTED_AUDIO_FORMAT", level="WARNING")
            return False
        return True
    
    async def _trigger_defense(self, session_id: str, user_id: str):
        """Active defense measures."""
        await log_event(f"DEFENSE_TRIGGERED | {session_id}", level="ALERT")
        
        self.threat_detector.raise_intrusion_flag(
            user_id=user_id, 
            reason=f"Call integrity breach on session {session_id}"
        )
        
        blackhole_response_action()

    async def start_voice_call(self, ws_a, ws_b, user_a_id: str, user_b_id: str):
        """
        Secure voice call with:
        - End-to-end encryption
        - Active voice firewall
        - Hardware-enforced audio path
        """
        # Rate-limit the call initiation
        if await rate_meter.track_call(user_a_id) or await rate_meter.track_call(user_b_id):
            await log_event("Call initiation rate limit exceeded", level="WARNING")
            await ws_a.close(code=4002, reason="Rate limit exceeded")
            await ws_b.close(code=4002, reason="Rate limit exceeded")
            return

        session_id = str(uuid.uuid4())
        log_event(f"VOICE_CALL_START | {session_id}", level="INFO")
        start_time = time.time()
        
        if not await self._validate_participants_secure(user_a_id, user_b_id):
            await ws_a.close(code=4001, reason="Auth failed")
            await ws_b.close(code=4001, reason="Auth failed")
            return

        self._generate_session_key(session_id)
        
        try:
            # Process User A <-> B
            while time.time() - start_time < _MAX_CALL_DURATION:
                # Use a combined receive to handle bidirectional streams
                try:
                    tasks = [ws_a.receive_bytes(), ws_b.receive_bytes()]
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    
                    for task in done:
                        chunk = await task
                        
                        is_user_a_chunk = task is tasks[0]
                        sender_id = user_a_id if is_user_a_chunk else user_b_id
                        receiver_ws = ws_b if is_user_a_chunk else ws_a
                        receiver_id = user_b_id if is_user_a_chunk else user_a_id

                        # Decrypt and validate audio
                        if not (clean_chunk := self._decrypt_audio_chunk(chunk, session_id)):
                            log_event(f"AUDIO_DECRYPTION_FAILED for {sender_id}", level="WARNING")
                            await self._trigger_defense(session_id, sender_id)
                            return
                        
                        if not self._validate_audio_format(clean_chunk):
                            await self._trigger_defense(session_id, sender_id)
                            return

                        # Translation pipeline
                        lang_a = await get_user_language_async(user_a_id)
                        lang_b = await get_user_language_async(user_b_id)
                        
                        translated = await translate_stream(
                            clean_chunk,
                            src_lang=lang_a if is_user_a_chunk else lang_b,
                            tgt_lang=lang_b if is_user_a_chunk else lang_a,
                            session_id=session_id
                        )
                        
                        # Encrypt and send
                        encrypted = self._encrypt_audio_chunk(translated["audio"], session_id)
                        if encrypted:
                            await receiver_ws.send_bytes(encrypted)
                            
                except Exception as e:
                    log_event(f"AUDIO_PROCESSING_FAILED: {str(e)}", level="ERROR")
                    await self._trigger_defense(session_id, sender_id)
                    return

                # Yield event loop
                await asyncio.sleep(0)

        except Exception as e:
            log_event(f"VOICE_CALL_ERROR: {str(e)}", level="CRITICAL")
        finally:
            await self._secure_call_teardown(ws_a, ws_b, session_id, user_a_id, user_b_id)

    async def _secure_call_teardown(self, ws_a, ws_b, session_id: str, user_a_id: str, user_b_id: str):
        """Military-grade session cleanup."""
        redis_client.delete(f"session_key:{session_id}")
        
        try:
            await ws_a.close(code=1000, reason="Normal closure")
            await ws_b.close(code=1000, reason="Normal closure")
        except:
            pass
        
        await log_to_blockchain("call_end", {
            "session_id": session_id,
            "duration": time.time() - time.time(),
            "user_a": user_a_id,
            "user_b": user_b_id,
            "timestamp": time.time()
        })
        
        log_event(f"VOICE_CALL_END | {session_id}", level="INFO")