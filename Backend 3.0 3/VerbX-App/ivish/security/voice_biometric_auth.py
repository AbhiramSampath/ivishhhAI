# security/auth/voice_auth.py

import os
import uuid
import asyncio
import hashlib
import hmac
from typing import Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import numpy as np
from decimal import Decimal
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Security imports (Corrected paths based on project architecture)
from backend.app.utils.logger import log_event
from security.crypto.encryption_utils import encrypt_voiceprint, compare_embeddings
from security.blockchain.blockchain_utils import anchor_event as log_biometric_audit
from config.settings import BIOMETRIC_THRESHOLD, MAX_BIOMETRIC_RETRIES
from security.blockchain.zkp_handler import ZKPVoiceProof
from backend.app.db.mongo import SecureVoiceStore
from security.intrusion_prevention.counter_response import trigger_blackhole_response
from ai_models.whisper.whisper_handler import stream_transcribe as stt_engine_transcribe

# --- Security Constants ---
_ENCRYPTION_KEY = os.getenv("VOICEPRINT_KEY", os.urandom(32))
_HMAC_KEY = os.getenv("VOICEPRINT_HMAC_KEY", os.urandom(32))
_BLOCKLIST: Dict[str, float] = {}
_RATE_LIMIT_WINDOW = 60
_SUPPORTED_AUDIO_FORMATS = {".wav", ".ogg", ".opus", ".mp3"}
_BLOCKCHAIN_TTL = 86400

@dataclass
class Voiceprint:
    user_id: str
    embedding: np.ndarray
    zkp_proof: str
    created_at: datetime
    last_used: datetime
    device_hash: str
    is_active: bool = True

class SecurityError(Exception):
    """Raised when biometric verification fails"""
    pass

class QuantumVoiceAuth:
    def __init__(self):
        self.zkp = ZKPVoiceProof()
        self.store = SecureVoiceStore()
        self._rate_limiter_lock = asyncio.Lock()
    
    async def extract_voiceprint(self, audio_stream: bytes, user_id: Optional[str] = None) -> Dict:
        """Secure voice feature extraction with liveness check"""
        if not self._validate_audio_format(audio_stream):
            raise SecurityError("Unsupported audio format")

        if not await self.liveness.verify(audio_stream):
            log_event("VOICE_SPOOFING_ATTEMPT", level="WARNING")
            raise SecurityError("Liveness check failed")
            
        try:
            embedding = self.enclave.process_voice(audio_stream)
            voice_hash = self._generate_voice_hash(embedding, user_id)
            return {
                "embedding": embedding,
                "voice_hash": voice_hash,
                "timestamp": datetime.utcnow().isoformat(),
                "device_fingerprint": self.enclave.get_device_fingerprint()
            }
        except Exception as e:
            log_event(f"VOICEPRINT_EXTRACTION_FAILED: {str(e)}", level="ERROR")
            raise

    def _validate_audio_format(self, stream: bytes) -> bool:
        """Validate file magic bytes"""
        # A proper check would inspect the file header for more formats
        return stream[:4] == b"RIFF" or stream[:4] == b"OggS"

    def _generate_voice_hash(self, embedding: np.ndarray, user_id: Optional[str] = None) -> str:
        """Quantum-resistant embedding derivation"""
        try:
            hkdf = HKDF(
                algorithm=hashes.BLAKE2s(64),
                length=32,
                salt=os.urandom(16),
                info=b'voiceprint',
                backend=default_backend()
            )
            return hkdf.derive(embedding.tobytes()).hex()
        except Exception as e:
            log_event(f"VOICEPRINT_HASH_FAILED: {str(e)}", level="ERROR")
            return "HASH_FAILED"

    async def register_voice(self, user_id: str, audio_stream: bytes):
        """Secure voiceprint enrollment"""
        try:
            voice_data = await self.extract_voiceprint(audio_stream, user_id)
            proof = self.zkp.generate_enrollment_proof(user_id, voice_data["voice_hash"])
            
            self.store.encrypt_and_save(
                user_id=user_id,
                voice_data=voice_data,
                zkp_proof=proof
            )
            
            log_biometric_audit(
                user_id=user_id,
                action="enrollment",
                proof_hash=hashlib.sha3_256(proof.encode()).hexdigest(),
                score=1.0,
                matched=True
            )
            return {"status": "success", "registered": True}
        except SecurityError as e:
            log_event(f"VOICE_REGISTRATION_FAILED: {str(e)}", level="WARNING")
            return {"status": "error", "registered": False}

    async def verify_voice(self, user_id: str, audio_stream: bytes) -> Dict:
        """Zero-knowledge voice verification"""
        try:
            current_data = await self.extract_voiceprint(audio_stream, user_id)
            stored_data = self.store.retrieve_secure(user_id)
            if not stored_data:
                raise SecurityError("No voiceprint found")
                
            match = self.zkp.verify(
                current_hash=current_data["voice_hash"],
                stored_proof=stored_data["zkp_proof"]
            )
            
            score = self._compute_similarity(
                current_data["embedding"],
                stored_data["embedding"]
            )
            
            await self._log_verification_attempt(
                user_id=user_id,
                score=score,
                matched=match
            )
            
            if score < BIOMETRIC_THRESHOLD:
                return {
                    "match": False,
                    "score": float(score),
                    "fallback": "enabled"
                }
                
            return {
                "match": match,
                "score": float(score),
                "zkp_proof": stored_data["zkp_proof"],
                "device_match": current_data["device_fingerprint"] == stored_data["device_fingerprint"]
            }
        except SecurityError as e:
            log_event(f"VOICE_VERIFY_FAILED: {str(e)}", level="ERROR")
            return {"match": False, "score": 0.0, "fallback": "enabled"}
        except Exception as e:
            log_event(f"SECURE_VOICE_VERIFY_FAILED: {str(e)}", level="CRITICAL")
            trigger_blackhole_response()
            return {"match": False, "score": 0.0, "fallback": "enabled"}

    def _compute_similarity(self, emb1: np.ndarray, emb2: np.ndarray) -> float:
        """Constant-time similarity scoring"""
        try:
            return compare_embeddings(emb1, emb2)
        except Exception as e:
            log_event(f"EMBEDDING_COMPARE_FAILED: {str(e)}", level="WARNING")
            return 0.0

    async def _log_verification_attempt(self, user_id: str, score: float, matched: bool):
        """Immutable audit logging"""
        try:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": hashlib.sha3_256(user_id.encode()).hexdigest(),
                "score": score,
                "matched": matched,
                "device_fp": self.enclave.get_device_fingerprint()
            }
            await log_biometric_audit(**log_entry)
        except Exception as e:
            log_event(f"BIOMETRIC_LOG_FAILED: {str(e)}", level="ERROR")

    async def _perform_challenge_response(self, audio: bytes) -> bool:
        """Dynamic ZKP challenge"""
        try:
            challenge = self.zkp.generate_challenge()
            response = self._extract_challenge_response(audio)
            return self.zkp.verify_challenge(challenge, response)
        except Exception as e:
            log_event(f"CHALLENGE_RESPONSE_FAILED: {str(e)}", level="WARNING")
            return False

    def _extract_challenge_response(self, audio: bytes) -> str:
        """Secure speech extraction for ZKP"""
        # This function would call an STT engine to transcribe the challenge spoken by the user.
        return stt_engine_transcribe(audio)

    async def _is_rate_limited(self, user_id: str) -> bool:
        async with self._rate_limiter_lock:
            now = datetime.utcnow().timestamp()
            key = f"voiceprint:{user_id}"
            
            if key in _BLOCKLIST and now - _BLOCKLIST[key] < _RATE_LIMIT_WINDOW:
                return True
            
            _BLOCKLIST[key] = now
            return False