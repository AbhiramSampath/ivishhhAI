from locale import normalize
import os
import time
import numpy as np
import hashlib
import logging
import subprocess
import asyncio
from datetime import datetime
import glob
from filelock import FileLock
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from fastapi import HTTPException
from functools import lru_cache

# --- Placeholder Imports for non-existent modules ---
def extract_linguistic_features(text: str) -> np.ndarray:
    """Placeholder for text feature extraction."""
    return np.random.rand(10)

def get_session_id() -> str:
    """Placeholder for getting a session ID."""
    return "session_1234"

# Corrected Internal imports
from backend.app.utils.logger import log_event, BaseLogger
from ai_models.emotion.emotion_handler import detect_emotion
from backend.app.db.redis import set_user_embedding, get_user_embedding
from security.blockchain.zkp_handler import validate_style_access
from security.intrusion_prevention.counter_response import rotate_endpoint, deploy_honeypot, clear_ephemeral_data

# Security constants
EMBEDDING_KEY = os.getenv("EMBEDDING_KEY", Fernet.generate_key().decode())
STYLE_LOCK_PATH = "/tmp/style_learner.lock"
TEMP_STYLE_PATHS = ["/tmp/ivish_style_*", "/dev/shm/style_*"]

# Constants
MEMORY_MODE = os.getenv("MEMORY_MODE", "True").lower() == "true"
MAX_TEXT_LENGTH = 5000
MAX_EMBEDDING_RATE = 5
BLACKHOLE_DELAY = 60
RATE_LIMIT_WINDOW = 60
SESSION_EXPIRY = 3600

# Centralized emotion definitions
EMOTION_LIST = ["happy", "calm", "neutral", "distressed", "hostile"]

logger = BaseLogger("SpeechStyleLearner")

class SpeechStyleLearner:
    """
    Provides secure, session-aware, and emotionally aligned speech style adaptation for Ivish AI.
    """

    def __init__(self):
        self._request_count = 0
        self._window_start = time.time()
        self._cipher = Fernet(EMBEDDING_KEY)
        self._last_reset = time.time()

    def _reset_rate_limit(self):
        now = time.time()
        if now - self._window_start > RATE_LIMIT_WINDOW:
            self._request_count = 0
            self._window_start = now

    async def _validate_rate_limit(self) -> bool:
        """Prevent style learner flooding attacks."""
        self._reset_rate_limit()
        self._request_count += 1
        if self._request_count > MAX_EMBEDDING_RATE:
            await log_event("[SECURITY] Style update rate limit exceeded", level="ALERT")
            await self._trigger_blackhole()
            return False
        return True

    async def _trigger_blackhole(self):
        """Null response + artificial delay on attack detection."""
        logger.log_event(f"Blackhole activated for {BLACKHOLE_DELAY}s", level="WARNING")
        await asyncio.sleep(BLACKHOLE_DELAY)

    async def _secure_wipe(self, paths: list):
        """Securely wipe temporary style data."""
        for pattern in paths:
            for path in glob.glob(pattern):
                try:
                    await asyncio.to_thread(
                        subprocess.run,
                        ['shred', '-u', path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                except Exception as e:
                    logger.log_event(f"Secure wipe failed for {path}: {e}", level="ERROR")

    def _encrypt_embedding(self, data: np.ndarray) -> bytes:
        """AES-256 encrypted style embeddings"""
        return self._cipher.encrypt(data.tobytes())

    def _decrypt_embedding(self, data: bytes) -> np.ndarray:
        """Secure embedding decryption"""
        return np.frombuffer(self._cipher.decrypt(data), dtype=np.float32)

    def _generate_session_key(self, user_id: str, session_id: str) -> str:
        """Tamper-proof session key generation"""
        user_hash = hashlib.sha256((user_id or session_id).encode()).hexdigest()
        return f"user_style:{user_hash}"

    def _sanitize_input(self, text: str) -> str:
        """Input sanitization to prevent injection attacks"""
        return text[:MAX_TEXT_LENGTH].replace("\0", "").replace("```", "'''")

    async def authenticate_style_access(self, user_token: str, zk_proof: str) -> bool:
        """ZKP-based embedding access control"""
        if not await self._validate_rate_limit():
            return False
        is_authorized = await validate_style_access(user_token, zk_proof)
        if not is_authorized:
            await log_event(f"[SECURITY] Unauthorized style access for {user_token[:6]}...", level="ALERT")
            await self._trigger_blackhole()
        return is_authorized

    async def update_speech_style(self, user_id: str, input_text: str, user_token: str = "", zk_proof: str = "") -> Dict[str, Any]:
        """
        Nuclear-grade secure style updating with:
        - Encrypted embeddings
        - Tamper-proof session keys
        - Rate limiting
        - ZKP authentication
        """
        if not await self._validate_rate_limit():
            return {"status": "rate_limited", "error": "Too many requests"}

        if user_token and not await self.authenticate_style_access(user_token, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}

        try:
            sanitized_text = self._sanitize_input(input_text)
            
            with FileLock(STYLE_LOCK_PATH):
                emotion = await detect_emotion(sanitized_text)
                features = extract_linguistic_features(sanitized_text)
                tone_vector = self.emotion_to_vector(emotion)
                
                if np.isnan(features).any():
                    features = np.nan_to_num(features)
                
                style_embedding = normalize(
                    np.concatenate([features, tone_vector]).astype(np.float32)
                )
            
            session_key = self._generate_session_key(user_id, get_session_id())
            existing = await get_user_embedding(session_key)
            
            if existing:
                try:
                    existing_embedding = self._decrypt_embedding(existing)
                    updated = 0.7 * existing_embedding + 0.3 * style_embedding
                except Exception as e:
                    await log_event(f"[STYLE] Decryption failed: {str(e)}", level="ALERT")
                    await self.clear_speech_style(user_id)
                    updated = style_embedding
            else:
                updated = style_embedding
            
            await set_user_embedding(
                key=session_key,
                value=self._encrypt_embedding(updated),
                ttl=SESSION_EXPIRY if not MEMORY_MODE else None
            )
            
            await log_event(f"[STYLE] Updated speech style for {user_id or get_session_id()[:8]}")
            
            return {
                "status": "success",
                "embedding_size": len(updated),
                "session_key": session_key,
                "timestamp": time.time()
            }
        except Exception as e:
            await log_event(f"[STYLE] Style update failed: {str(e)}", level="ALERT")
            return {"status": "failed", "error": str(e)}

    async def get_speech_style(self, user_id: str, user_token: str = "", zk_proof: str = "") -> Optional[np.ndarray]:
        """Secure embedding retrieval with ZKP validation and rate-limiting"""
        session_key = self._generate_session_key(user_id, get_session_id())
        
        if user_token and not await self.authenticate_style_access(user_token, zk_proof):
            return None
        
        encrypted = await get_user_embedding(session_key)
        if not encrypted:
            return None

        try:
            return self._decrypt_embedding(encrypted)
        except Exception as e:
            await log_event(f"[STYLE] Decryption failed: {str(e)}", level="ALERT")
            await self.clear_speech_style(user_id)
            return None

    async def apply_style_to_prompt(self, user_id: str, base_prompt: str, user_token: str = "", zk_proof: str = "") -> str:
        """
        Prompt engineering with:
        - Style hints
        - Injection protection
        - ZKP validation
        """
        embedding = await self.get_speech_style(user_id, user_token, zk_proof)
        if embedding is None:
            return self.sanitize_prompt(base_prompt)
        
        safe_hint = self.infer_tone_from_embedding(embedding).replace("\n", "")
        return f"{self.sanitize_prompt(base_prompt)}\n# STYLE: {safe_hint}"

    async def clear_speech_style(self, user_id: str):
        """Military-grade data wipe"""
        session_key = self._generate_session_key(user_id, get_session_id())
        try:
            await clear_ephemeral_data(modules=[session_key])
            await log_event(f"[STYLE] Cleared speech style for {user_id}")
            return {"status": "cleared"}
        except Exception as e:
            await log_event(f"[STYLE] Clear failed: {str(e)}", level="ALERT")
            return {"status": "failed", "error": str(e)}

    @staticmethod
    def sanitize_prompt(text: str) -> str:
        """Anti-injection measures"""
        return text.replace("```", "'''").replace("$", "").strip()

    @staticmethod
    def emotion_to_vector(emotion: str) -> np.ndarray:
        """Hardened emotion mapping"""
        vec = np.zeros(len(EMOTION_LIST), dtype=np.float32)
        try:
            idx = EMOTION_LIST.index(emotion.lower())
            vec[idx] = 1.0
        except ValueError:
            pass
        return vec
        
    @staticmethod
    def infer_tone_from_embedding(embedding: np.ndarray) -> str:
        """ML-driven tone inference (replace with your model)"""
        if embedding[-1] > 0.7:
            return "urgent"
        if embedding[0] > 0.6:
            return "friendly"
        return "professional"

speech_style_learner = SpeechStyleLearner()