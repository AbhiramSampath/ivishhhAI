import os
import time
import numpy as np
import hashlib
import logging
import asyncio
import json
from datetime import datetime
from typing import Dict, Optional, Union
from collections import defaultdict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# SECURITY: Corrected imports
from db.redis import redis_db
from utils.logger import log_event
from ai_models.voice_biometrics.voice_encoder import get_embedding
from security.blockchain.blockchain_utils import log_to_blockchain
from security.device_fingerprint import get_hardware_fingerprint
from utils.helpers import apply_differential_privacy
from security.intrusion_prevention.counter_response import BlackholeRouter as SecureWiper

# LOGGER CONFIG
logger = logging.getLogger(__name__)

# SECURITY CONSTANTS - Defined locally as config file is not in PDF
VOICE_AUTH_SALT = os.getenv("VOICE_AUTH_SALT", "voice_auth_salt").encode()
EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", 256))
MIN_VOICE_LENGTH = float(os.getenv("MIN_VOICE_LENGTH", 1.5))
MAX_VOICE_LENGTH = float(os.getenv("MAX_VOICE_LENGTH", 10.0))
AUTH_THRESHOLD = float(os.getenv("AUTH_THRESHOLD", 0.82))
KDF_ITERATIONS = int(os.getenv("KDF_ITERATIONS", 100000))
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", 5))
LOCKOUT_DURATION = int(os.getenv("LOCKOUT_DURATION", 30))
_VOICE_ENCRYPTION_KEY = os.getenv("VOICE_ENCRYPTION_KEY", os.urandom(32)).encode()

class SecureVoiceDB:
    def __init__(self):
        self._key = self._derive_key(VOICE_AUTH_SALT)

    def _derive_key(self, salt: bytes) -> bytes:
        try:
            fingerprint = get_hardware_fingerprint()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=KDF_ITERATIONS,
                backend=default_backend()
            )
            return kdf.derive(fingerprint)
        except Exception as e:
            logger.critical("Voice key derivation failed", exc_info=True)
            return b"\x00" * 32

    async def store(self, user_id: str, embedding: np.ndarray):
        try:
            cipher = AESGCM(self._key)
            nonce = os.urandom(12)
            encrypted = cipher.encrypt(nonce, embedding.tobytes(), None)
            await redis_db.set_key(f"voice_emb:{user_id}", nonce + encrypted)
        except Exception as e:
            logger.warning("Voice embedding storage failed", exc_info=True)

    async def retrieve(self, user_id: str) -> Optional[np.ndarray]:
        try:
            encrypted = await redis_db.get_key(f"voice_emb:{user_id}")
            if not encrypted: raise ValueError("User not found")
            
            cipher = AESGCM(self._key)
            nonce, ciphertext = encrypted[:12], encrypted[12:]
            raw_data = cipher.decrypt(nonce, ciphertext, None)
            
            return np.frombuffer(raw_data, dtype=np.float32)
        except Exception as e:
            logger.warning("Voice retrieval failed", exc_info=True)
            return None

    async def record_attempt(self, user_id: str):
        now = time.time()
        await redis_db.lpush(f"voice_attempts:{user_id}", now)
        await redis_db.expire(f"voice_attempts:{user_id}", LOCKOUT_DURATION)

    async def is_locked_out(self, user_id: str) -> bool:
        attempts = await redis_db.llen(f"voice_attempts:{user_id}")
        return attempts >= MAX_ATTEMPTS

    async def reset_attempts(self, user_id: str):
        await redis_db.delete_key(f"voice_attempts:{user_id}")

_voice_db = SecureVoiceDB()

async def _validate_audio(audio_path: str) -> bool:
    try:
        if not await asyncio.to_thread(os.path.exists, audio_path): return False
        return True
    except Exception as e:
        logger.warning("Audio validation failed", exc_info=True)
        return False

async def register_voice(user_id: str, audio_path: str) -> Dict:
    start_time = time.time()
    try:
        if not await _validate_audio(audio_path): return {"status": "error", "reason": "Invalid audio"}
        if await _voice_db.is_locked_out(user_id): return {"status": "locked", "reason": "Too many attempts"}
        
        embedding = await asyncio.to_thread(get_embedding, audio_path)
        if embedding is None: return {"status": "error", "reason": "Embedding generation failed"}
        
        norm = np.linalg.norm(embedding)
        if abs(norm - 1.0) > 1e-6: embedding = embedding / norm

        await _voice_db.store(user_id, embedding)
        await _voice_db.reset_attempts(user_id)
        
        await log_to_blockchain("voice_register", {"user_id": user_id, "timestamp": datetime.utcnow().isoformat() + "Z", "status": "success"})
        await _apply_processing_delay(start_time, target_ms=200)
        
        return {"status": "success", "message": "Voice registered successfully"}
    except Exception as e:
        logger.warning("Voice registration failed", exc_info=True)
        await log_to_blockchain("voice_register", {"user_id": user_id, "timestamp": datetime.utcnow().isoformat() + "Z", "status": "failed"})
        return {"status": "error", "reason": "Registration failed"}

async def verify_voice(user_id: str, audio_sample: str) -> Dict:
    start_time = time.time()
    try:
        if not await _validate_audio(audio_sample): return {"status": "error", "reason": "Invalid audio sample"}
        if await _voice_db.is_locked_out(user_id): return {"status": "locked", "reason": "Account locked"}
        
        stored_emb = await _voice_db.retrieve(user_id)
        if stored_emb is None: return {"status": "error", "reason": "No voiceprint found"}
        
        live_emb = await asyncio.to_thread(get_embedding, audio_sample)
        if live_emb is None: return {"status": "error", "reason": "Embedding generation failed"}
        
        live_emb = apply_differential_privacy({"emb": live_emb}, epsilon=0.01)["emb"]
        score = _secure_cosine_sim(stored_emb, live_emb)
        auth_result = score >= AUTH_THRESHOLD

        await log_to_blockchain("voice_auth", {"user_id": user_id, "score": float(score), "result": auth_result, "timestamp": datetime.utcnow().isoformat() + "Z"})

        if auth_result: await _voice_db.reset_attempts(user_id)
        else: await _voice_db.record_attempt(user_id)

        await _apply_processing_delay(start_time, target_ms=200)

        return {"status": "success" if auth_result else "failed", "authenticated": auth_result, "score": float(score)}
    except Exception as e:
        logger.warning("Voice auth error", exc_info=True)
        return {"status": "error", "authenticated": False, "reason": "Authentication failed"}

def _secure_cosine_sim(emb1: np.ndarray, emb2: np.ndarray) -> float:
    try:
        emb1_norm = emb1 / np.linalg.norm(emb1)
        emb2_norm = emb2 / np.linalg.norm(emb2)
        dot_product = np.sum(emb1_norm * emb2_norm)
        return dot_product
    except Exception as e:
        logger.warning("Cosine similarity failed", exc_info=True); return 0.0

async def _apply_processing_delay(start_time: float, target_ms: int):
    elapsed_ms = (time.time() - start_time) * 1000
    if elapsed_ms < target_ms: await asyncio.sleep((target_ms - elapsed_ms) / 1000)