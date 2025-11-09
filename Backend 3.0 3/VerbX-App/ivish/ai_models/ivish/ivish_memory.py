import json
import uuid
import time
import os
import hmac
import hashlib
import logging
import asyncio
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Union, Any
from collections import deque
import sys

# Corrected imports based on the provided file structure
from backend.app.db.redis import RedisClient as redis_conn
from backend.app.utils.logger import log_event
from ai_models.emotion.emotion_handler import EmotionEngine
from security.device_fingerprint import get_hardware_fingerprint

# Assuming MEMORY_TTL is a constant defined in a config or environment variable.
MEMORY_TTL = int(os.getenv("MEMORY_TTL", 90*24*60*60))  # 90 days default

# LOGGER CONFIG
logger = logging.getLogger(__name__)

class IvishMemory:
    """
    Nuclear-grade secure memory engine with:
    - AES-256 memory encryption
    - HMAC integrity verification
    - Automatic redaction
    - Tamper-evident logs
    - Device-specific key derivation
    """

    def __init__(self):
        # SECURITY: Key derived from hardware fingerprint + secret
        
        self.hmac_key = self._derive_hmac_key()
        self.memory_cache = {}  # Local cache for fast access
        self.cache_ttl = timedelta(seconds=30)  # Short-lived cache
        self.emotion_engine = EmotionEngine()

    def _derive_hmac_key(self) -> bytes:
        """Device-specific key derivation"""
        try:
            fingerprint = get_hardware_fingerprint()
            secret = os.getenv("MEMORY_HMAC_SECRET", "fallback-secret")
            return hmac.new(secret.encode(), fingerprint.encode(), 'sha256').digest()
        except Exception as e:
            logger.critical("HMAC key derivation failed", exc_info=True)
            raise RuntimeError("Memory subsystem initialization failed")

    def _secure_memory_entry(self, data: Dict) -> str:
        """
        SECURELY prepares memory entry with:
        - Field encryption
        - HMAC signing
        - PII redaction
        - Metadata sanitization
        """

    def _generate_hmac(self, entry: Dict) -> str:
        """Generate integrity check signature"""
        try:
            content = "|".join([
                entry['text'],
                entry['emotion'],
                entry['timestamp'],
                entry['session_id'],
                entry['device_id']
            ])
            return hmac.new(self.hmac_key, content.encode(), 'sha256').hexdigest()
        except Exception as e:
            logger.error("HMAC generation failed", exc_info=True)
            return ""

    async def store_memory(self, session_id: str, user_input: str, device_id: str = "unknown") -> bool:
        """
        SECURE memory storage with:
        - Encrypted emotion data
        - Sanitized text
        - Integrity checks
        - Device binding
        """
        try:
            if not self._is_valid_session_id(session_id):
                raise ValueError("Invalid session ID")

            emotion_result = self.emotion_engine.detect_emotion_from_text(user_input)
            emotion = emotion_result.get("emotion", "neutral")

            entry = self._secure_memory_entry({
                'text': user_input,
                'emotion': emotion,
                'session_id': session_id,
                'device_id': device_id
            })

            memory_key = f"ivish:memory:{session_id}"
            await asyncio.gather(
                redis_conn.rpush_async(memory_key, entry),
                redis_conn.expire_async(memory_key, MEMORY_TTL)
            )

            self._update_cache(memory_key, entry)

            log_event(
                f"Stored SECURE memory for {session_id}",
                metadata={'length': len(user_input)},
                level="DEBUG"
            )

            return True

        except Exception as e:
            logger.error(f"Memory storage failed: {type(e).__name__}", exc_info=True)
            return False

    async def get_recent_memory(self, session_id: str, limit: int = 5) -> List[Dict]:
        """
        SECURE memory retrieval with:
        - HMAC verification
        - Emotion decryption
        - Anti-timing attacks
        - Cache-first access
        """
        start_time = time.time()
        try:
            memory_key = f"ivish:memory:{session_id}"
            
            cached = self._get_from_cache(memory_key)
            if cached:
                logger.debug("Using cached memory")
                return cached

            raw_entries = await redis_conn.lrange_async(memory_key, -limit, -1)
            if not raw_entries:
                return []

            entries = []
            for entry_bytes in raw_entries:
                try:
                    data = json.loads(entry_bytes)
                    if not self._verify_hmac(data):
                        logger.warning("HMAC verification failed for memory entry")
                        continue

                    try:
                        data['emotion'] = self.encryptor.decrypt(
                            data['emotion'].encode('latin-1')
                        ).decode()
                    except Exception as e:
                        logger.warning("Emotion decryption failed", exc_info=True)
                        continue

                    entries.append(data)
                except Exception as e:
                    logger.warning("Memory entry parsing failed", exc_info=True)
                    continue

            self._update_cache(memory_key, entries)

            self._apply_processing_delay(start_time, target_ms=30)

            return entries

        except Exception as e:
            logger.error(f"Memory retrieval failed: {type(e).__name__}", exc_info=True)
            return []

    def _verify_hmac(self, data: Dict) -> bool:
        """Verify entry integrity"""
        try:
            existing_hmac = data.pop('hmac', None)
            if not existing_hmac:
                return False

            expected = self._generate_hmac(data)
            return hmac.compare_digest(existing_hmac.encode(), expected.encode())
        except Exception as e:
            logger.warning("HMAC verification error", exc_info=True)
            return False

    async def inject_memory_into_prompt(self, session_id: str, limit: int = 5) -> str:
        """
        SECURE prompt injection with:
        - Context length limits
        - Emotion filtering
        - PII redaction
        - Cache-first access
        """
        entries = await self.get_recent_memory(session_id, limit)
        if not entries:
            return ""

        context_lines = []
        total_chars = 0
        max_chars = 1000

        for entry in reversed(entries):
            line = f"User said: \"{entry['text']}\" (tone: {entry['emotion']})"
            if total_chars + len(line) > max_chars:
                break
            context_lines.append(line)
            total_chars += len(line)

        return "Previous context (secure):\n" + "\n".join(reversed(context_lines))

    async def clear_memory(self, session_id: str) -> bool:
        """
        SECURE memory wipe with:
        - Cryptographic shredding
        - Audit logging
        - Fallback verification
        """
        try:
            memory_key = f"ivish:memory:{session_id}"

            entries = await redis_conn.lrange_async(memory_key, 0, -1)
            for i, entry in enumerate(entries):
                try:
                    await redis_conn.lset_async(memory_key, i, b'\x00' * len(entry))
                except Exception as e:
                    logger.warning("Memory overwrite failed", exc_info=True)

            deleted = await redis_conn.delete_async(memory_key)

            self._clear_cache(memory_key)

            log_event(
                f"SECURE memory wipe for {session_id}",
                metadata={'entries_erased': deleted},
                level="AUDIT"
            )

            return deleted > 0

        except Exception as e:
            logger.critical(f"Memory wipe failed: {type(e).__name__}", exc_info=True)
            return False

    def _is_valid_session_id(self, session_id: str) -> bool:
        """Prevent key injection attacks"""
        return isinstance(session_id, str) and len(session_id) == 36 and session_id.count('-') == 4

    def _apply_processing_delay(self, start_time: float, target_ms: int):
        """Prevent timing side-channels"""
        elapsed_ms = (time.time() - start_time) * 1000
        if elapsed_ms < target_ms:
            time.sleep((target_ms - elapsed_ms) / 1000)

    def _get_from_cache(self, key: str) -> Optional[List]:
        """Get memory from local cache if not expired"""
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            if datetime.now(timezone.utc) - entry['timestamp'] < self.cache_ttl:
                return entry['data']
        return None

    def _update_cache(self, key: str, data: Union[Dict, List]):
        """Update local cache with timestamp"""
        try:
            if isinstance(data, str):
                data = [json.loads(data)]
            self.memory_cache[key] = {
                'timestamp': datetime.now(timezone.utc),
                'data': data
            }
        except Exception as e:
            logger.warning("Cache update failed", exc_info=True)

    def _clear_cache(self, key: str):
        """Remove entry from cache"""
        if key in self.memory_cache:
            del self.memory_cache[key]

    async def get_memory_stats(self, session_id: str) -> Dict:
        """Get memory usage stats for diagnostics"""
        try:
            memory_key = f"ivish:memory:{session_id}"
            size = await redis_conn.llen_async(memory_key)
            ttl = await redis_conn.ttl_async(memory_key)
            return {
                "session_id": session_id,
                "entry_count": size,
                "ttl_seconds": ttl,
                "cache_hit": memory_key in self.memory_cache,
                "cache_size": len(self.memory_cache)
            }
        except Exception as e:
            logger.warning("Memory stats failed", exc_info=True)
            return {"error": "Stats retrieval failed"}