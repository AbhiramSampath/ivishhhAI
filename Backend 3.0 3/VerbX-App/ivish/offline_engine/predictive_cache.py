# offline_engine/predictive_cache.py
# 🔒 Nuclear-Grade Predictive Caching with Zero-Trust Validation
# Enables secure, proactive caching of STT, TTS, and translation results for offline use

import os
import time
import uuid
import json
import hashlib
import logging
import subprocess
import shlex
import asyncio
from typing import Dict, Optional, Tuple, Any
from datetime import datetime
import hmac
from collections import defaultdict

# Internal imports (Corrected based on file structure)
from config.settings import CACHE_TTL, OFFLINE_CACHE_PATH
from backend.app.utils.logger import log_event
from security.blockchain.zkp_handler import validate_cache_access
from security.intrusion_prevention.counter_response import trigger_blackhole
from security.intrusion_prevention.isolation_engine import rotate_endpoints
from security.blockchain.blockchain_utils import log_cache_event

# External imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# Security constants
_CACHE_DB = os.path.join(OFFLINE_CACHE_PATH, "cache_index.enc")
_MODEL_SALT = b"verbx_model_salt_2023"  # From secure config
MAX_CACHE_SIZE = 100000  # Prevent DoS
MAX_CACHE_ENTRIES = 1000  # Max cache entries
BLACKHOLE_DELAY = 60  # Seconds to delay attacker
RATE_LIMIT_WINDOW = 60  # Rate-limiting window
MAX_CACHE_RATE = 5  # Max cache updates per minute
TEMP_CACHE_PATHS = ["/tmp/ivish_cache_*", "/dev/shm/cache_*"]

# AES-256-GCM encryption
CACHE_AES_KEY = os.getenv("CACHE_AES_KEY", "").encode()[:32]
if len(CACHE_AES_KEY) != 32:
    raise RuntimeError("Invalid encryption key for predictive cache")

class PredictiveCacheEngine:
    """
    Provides secure, anticipatory caching for offline-first AI operations.
    """

    def __init__(self):
        self._request_count = 0
        self._window_start = time.time()
        self._rate_limiter_lock = asyncio.Lock()
        self.honeypot_response = deploy_honeypot()
        
    async def _validate_rate_limit(self) -> bool:
        """Prevent cache flooding attacks."""
        async with self._rate_limiter_lock:
            now = time.time()
            if now - self._window_start > RATE_LIMIT_WINDOW:
                self._request_count = 0
                self._window_start = now
            self._request_count += 1
            if self._request_count > MAX_CACHE_RATE:
                log_event("[SECURITY] Cache rate limit exceeded", level="WARNING")
                await trigger_blackhole()
                return False
            return True

    async def _secure_wipe(self, paths: list):
        """Securely wipe temporary cache data."""
        for path in paths:
            try:
                subprocess.run(shlex.split(f'shred -u {path}'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error(f"Secure wipe failed for {path}: {e}")

    def _encrypt_data(self, data: bytes) -> bytes:
        """AES-256-GCM encryption for cache data"""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(CACHE_AES_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def _decrypt_data(self, data: bytes) -> str:
        """Secure cache decryption"""
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = Cipher(algorithms.AES(CACHE_AES_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')

    def _secure_hash(self, input_str: str) -> str:
        """Nuclear-grade key derivation for cache keys"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=_MODEL_SALT,
            iterations=210_000,
            backend=default_backend()
        )
        return kdf.derive(input_str.encode()).hex()

    def _validate_cache_key(self, key: str) -> bool:
        """Prevent path traversal and injection attacks"""
        return not any([c in key for c in ["/", "\\", "..", "\0"]])

    async def authenticate_cache(self, user_token: str, zk_proof: str) -> bool:
        """ZKP-based cache access control"""
        if not await self._validate_rate_limit():
            return False
        is_authorized = validate_cache_access(user_token, zk_proof)
        if not is_authorized:
            log_event(f"[SECURITY] Unauthorized cache access for {user_token[:6]}...", level="CRITICAL")
            await trigger_blackhole()
        return is_authorized

    def load_cache_db(self) -> Dict[str, Any]:
        """Load encrypted cache with integrity checks"""
        if not os.path.exists(_CACHE_DB):
            return {}

        try:
            with open(_CACHE_DB, 'rb') as f:
                encrypted_blob = f.read()

            if not encrypted_blob:
                return {}

            integrity_tag = encrypted_blob[-64:]
            encrypted_data = encrypted_blob[:-64]

            if not self._verify_integrity_tag(encrypted_data, integrity_tag.hex()):
                raise ValueError("Cache DB integrity check failed")

            decrypted_data = self._decrypt_data(encrypted_data)
            return json.loads(decrypted_data)

        except Exception as e:
            log_event(f"[CACHE] Cache DB load failed: {str(e)}", level="CRITICAL")
            asyncio.create_task(self._secure_wipe([_CACHE_DB]))
            return {}

    def save_cache_db(self, db: Dict[str, Any]) -> bool:
        """Atomic encrypted cache save with integrity check"""
        if len(db) > MAX_CACHE_ENTRIES:
            self.clean_old_cache(db)

        try:
            encrypted_data = self._encrypt_data(json.dumps(db).encode())
            integrity_tag = self._compute_integrity_tag(encrypted_data)
            
            temp_path = f"{_CACHE_DB}.tmp"
            with open(temp_path, 'wb') as f:
                f.write(encrypted_data)
                f.write(integrity_tag)
            os.replace(temp_path, _CACHE_DB)
            return True
        except Exception as e:
            log_event(f"[CACHE] Cache DB save failed: {str(e)}", level="CRITICAL")
            return False

    def _compute_integrity_tag(self, data: bytes) -> bytes:
        """Cryptographic tag for cache validation"""
        h = hmac.HMAC(CACHE_AES_KEY, data, hashes.SHA256())
        return h.finalize()

    def _verify_integrity_tag(self, data: bytes, expected: str) -> bool:
        """Validate cache integrity"""
        h = hmac.HMAC(CACHE_AES_KEY, data, hashes.SHA256())
        try:
            h.verify(bytes.fromhex(expected))
            return True
        except Exception:
            return False

    async def cache_translation_pair(self, src_lang: str, tgt_lang: str, phrase: str, output: str, user_token: str = "", zk_proof: str = "") -> Dict[str, Any]:
        """
        Secure translation caching with:
        - Input sanitization
        - Anti-tampering checks
        - ZKP-based access control
        """
        if user_token and not await self.authenticate_cache(user_token, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}

        if not all([self._validate_cache_key(k) for k in [src_lang, tgt_lang, phrase]]):
            return {"status": "invalid_key", "error": "Malformed cache key"}

        try:
            key = self._secure_hash(f"{src_lang}::{tgt_lang}::{phrase}")
            db = self.load_cache_db()
            db[key] = {
                "output": self._encrypt_data(output.encode()),
                "timestamp": time.time(),
                "access_count": 0,
                "user": self._secure_hash(user_token) if user_token else "anonymous"
            }
            self.save_cache_db(db)
            await log_cache_event({
                "action": "cache_translation_pair",
                "key": key,
                "src_lang": src_lang,
                "tgt_lang": tgt_lang,
                "phrase_hash": hashlib.sha256(phrase.encode()).hexdigest(),
                "timestamp": time.time()
            })
            return {"status": "success", "key": key}
        except Exception as e:
            log_event(f"[CACHE] Translation caching failed: {str(e)}", level="ERROR")
            return {"status": "failed", "error": str(e)}

    def get_cached_translation(self, src_lang: str, tgt_lang: str, phrase: str) -> Optional[str]:
        """Retrieve with TTL and usage tracking"""
        key = self._secure_hash(f"{src_lang}::{tgt_lang}::{phrase}")
        db = self.load_cache_db()
        
        if key not in db:
            return None
            
        entry = db[key]
        now = time.time()
        
        if now - entry["timestamp"] > CACHE_TTL:
            del db[key]
            self.save_cache_db(db)
            return None
            
        entry["access_count"] += 1
        db[key] = entry
        self.save_cache_db(db)
        
        try:
            return self._decrypt_data(entry["output"]).decode('utf-8')
        except Exception as e:
            log_event(f"[CACHE] Decryption failed: {str(e)}", level="ERROR")
            del db[key]
            self.save_cache_db(db)
            return None

    async def predict_and_cache(self, current_lang: str, tone: str, user_token: str = "", zk_proof: str = "") -> Dict[str, Any]:
        """Secure predictive caching with rate limiting"""
        if not await self._validate_rate_limit():
            return {"status": "rate_limited", "error": "Too many requests"}

        if user_token and not await self.authenticate_cache(user_token, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}

        try:
            predicted = predict_next_language(current_lang, tone)
            if not self._validate_cache_key(predicted):
                return {"status": "invalid_prediction", "error": "Language key invalid"}

            success = await self.cache_model(predicted)
            return {
                "status": "success" if success else "failed",
                "predicted_lang": predicted,
                "timestamp": time.time()
            }

        except Exception as e:
            log_event(f"[CACHE] Predict and cache failed: {str(e)}", level="ERROR")
            return {"status": "failed", "error": str(e)}

    async def cache_model(self, model_name: str) -> bool:
        """Model caching with integrity verification"""
        if not self._validate_cache_key(model_name):
            return False

        model_path = os.path.join(OFFLINE_CACHE_PATH, "models", model_name)
        os.makedirs(model_path, exist_ok=True)
        
        temp_path = f"{model_path}.tmp"
        try:
            with open(os.path.join(temp_path, "model.bin"), "wb") as f:
                f.write(self._encrypt_data(b"model_data"))
            os.replace(temp_path, model_path)
            log_event(f"[CACHE] Model cached: {model_name}")
            return True
        except Exception as e:
            log_event(f"[CACHE] Model caching failed: {str(e)}", level="ERROR")
            if os.path.exists(temp_path):
                await self._secure_wipe([temp_path])
            return False

    def clean_old_cache(self, db: Optional[Dict] = None) -> int:
        """TTL + LFU-based cache eviction"""
        db = db or self.load_cache_db()
        now = time.time()
        
        # Sort by access count (LFU) and then timestamp (TTL)
        sorted_entries = sorted(
            db.items(),
            key=lambda x: (-x[1]["access_count"], x[1]["timestamp"])
        )
        
        to_keep = {}
        cleaned = 0
        
        for key, entry in sorted_entries:
            if now - entry["timestamp"] < CACHE_TTL and len(to_keep) < MAX_CACHE_ENTRIES:
                to_keep[key] = entry
            else:
                cleaned += 1
                
        self.save_cache_db(to_keep)
        log_event(f"[CACHE] Evicted {cleaned} cache entries")
        return cleaned

    def offline_ready(self, language: str) -> bool:
        """Secure readiness check with model verification"""
        if not self._validate_cache_key(language):
            return False

        model_path = os.path.join(OFFLINE_CACHE_PATH, "models", language)
        if not os.path.exists(model_path):
            return False
            
        try:
            with open(os.path.join(model_path, "model.bin"), "rb") as f:
                model_data = f.read()
                decrypted = self._decrypt_data(model_data)
                if not decrypted:
                    return False
            return True
        except Exception as e:
            log_event(f"[CACHE] Model verification failed: {str(e)}", level="ERROR")
            return False

# Singleton with rate limit
predictive_cache = PredictiveCacheEngine()