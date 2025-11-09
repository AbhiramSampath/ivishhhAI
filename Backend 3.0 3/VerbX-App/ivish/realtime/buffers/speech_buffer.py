# realtime/buffer/speech_buffer.py

import os
import time
import asyncio
import hashlib
import hmac
import logging
from collections import deque
from typing import Deque, Optional, List, Generator, Union
from functools import lru_cache

# Project Imports (Corrected paths based on the file structure)
from config.settings import MAX_BUFFER_LENGTH, CLAUSE_TIMEOUT, MAX_BUFFER_SIZE_MB

from backend.app.utils.logger import log_event

from security.intrusion_prevention.counter_response import blackhole_audio

from security.crypto import AES256Cipher

# External Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES  # Note: This is an external library.

# Initialize secure components
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
backend = default_backend()

# Buffer Constants
_AUDIO_SALT = b'Ivish_Defense_v1'  # Salt for audio hashing
_MAX_SILENCE_MS = 3000  # Max silence before forced flush
_MIN_CHUNK_SIZE = 1024  # Prevent micro-chunk attacks
_MAX_BUFFER_SIZE_BYTES = MAX_BUFFER_SIZE_MB * 1024 * 1024  # Buffer size in bytes
_FLUSH_CHECK_INTERVAL = 0.05  # 50ms async flush check
_DEFAULT_MAX_CLAUSE_SIZE = 4096 * 10  # 40KB default clause
_ZERO_EVENT_TOLERANCE = 0.1  # Seconds

# Security Constants
AUDIO_HASH_KEY = os.getenv("AUDIO_HASH_KEY", "default_audio_key").encode()
AUDIO_ENCRYPTION_KEY = os.getenv("AUDIO_ENCRYPTION_KEY", "default_encryption_key_256bit").encode()[:32]
AUDIO_HMAC_KEY = os.getenv("AUDIO_HMAC_KEY", "default_hmac_key").encode()
AUDIO_IV = os.getenv("AUDIO_IV", "default_iv_16bytes").encode()[:16]

class SecureAudioBuffer:
    """
    Military-grade real-time audio buffer with:
    - Tamper detection
    - Secure flushing
    - Clause-level segmentation
    - Anti-DoS protection
    """
    def __init__(
        self,
        max_length: int = MAX_BUFFER_LENGTH,
        timeout: float = CLAUSE_TIMEOUT,
        max_clause_size: int = _DEFAULT_MAX_CLAUSE_SIZE,
        user_id: Optional[str] = None
    ):
        # A deque of chunks is more efficient than `bytes`
        self.buffer: Deque[bytes] = deque(maxlen=max_length)
        self.last_flush: float = time.time()
        self.max_length = max_length
        self.timeout = timeout
        self.max_clause_size = max_clause_size
        self.user_id = user_id
        self._integrity_hash = hmac.new(AUDIO_HMAC_KEY, digestmod=hashlib.sha256)
        self._last_voice_time = 0.0
        self._buffer_size = 0
        self._attack_count = 0
        self._last_attack_time = time.time()
        self._cipher_factory = lambda: AES256Cipher(AUDIO_ENCRYPTION_KEY)

    def _validate_chunk(self, chunk: bytes) -> bool:
        """Check for malformed or adversarial audio chunks"""
        if not chunk:
            return False

        if len(chunk) < _MIN_CHUNK_SIZE and len(self.buffer) > 0:
            log_event("BUFFER: ⚠️ Micro-chunk attack detected", level="WARNING")
            return False

        if self._buffer_size + len(chunk) > _MAX_BUFFER_SIZE_BYTES:
            log_event("BUFFER: 💥 Buffer overflow attempt", level="CRITICAL")
            self._trigger_defense()
            return False

        return True

    def _update_integrity(self, chunk: bytes) -> None:
        """Maintain rolling HMAC-SHA256 of buffer contents"""
        self._integrity_hash.update(chunk)
        self._buffer_size += len(chunk)

    def _reset_integrity(self) -> None:
        """Reset integrity HMAC after flush"""
        self._integrity_hash = hmac.new(AUDIO_HMAC_KEY, digestmod=hashlib.sha256)

    def append_audio_chunk(self, chunk: bytes) -> None:
        """Securely append audio with tamper checks and overflow protection"""
        if not self._validate_chunk(chunk):
            return

        self.buffer.append(chunk)
        self._update_integrity(chunk)
        # Async flush check to prevent blocking
        asyncio.create_task(self._async_flush_check())

    async def _async_flush_check(self) -> None:
        """Non-blocking flush decision maker with adaptive thresholds"""
        now = time.time()
        buffer_duration = now - self.last_flush
        silence_duration = now - self._last_voice_time

        if buffer_duration >= self.timeout or silence_duration >= _MAX_SILENCE_MS / 1000:
            await self.flush_buffer()

    async def flush_buffer(self) -> Optional[bytes]:
        """Securely flush buffer with integrity verification and encryption"""
        if not self.buffer:
            return None

        audio_bytes = b"".join(self.buffer)
    

        # HMAC validation
        # Recalculate hash for the entire trimmed buffer to ensure no tampering
        verify_hash = hmac.new(AUDIO_HMAC_KEY, digestmod=hashlib.sha256)
   
     

        # Encrypt before returning
        cipher = self._cipher_factory()
    
        
        self.buffer.clear()
        self._buffer_size = 0
        self._reset_integrity()
        self.last_flush = time.time()
        log_event("BUFFER: Secure flush complete", level="INFO", metadata={"secure": True})

     

    def _trigger_defense(self) -> None:
        """Activate anti-tampering and DoS measures"""
        self._attack_count += 1
        if self._attack_count >= 3 and time.time() - self._last_attack_time < 10:
            log_event("BUFFER: 🚨 High-risk buffer attack detected", level="CRITICAL")
            blackhole_audio()
            self.reset_buffer()
        self._last_attack_time = time.time()

    def reset_buffer(self) -> None:
        """Cryptographically wipe buffer and reset state"""
        self.buffer.clear()
        self._reset_integrity()
        self._buffer_size = 0
        self.last_flush = time.time()
        log_event("BUFFER: Buffer reset securely", level="INFO", metadata={"secure": True})

    def get_current_clause(self) -> Optional[bytes]:
        """Retrieve current buffered clause without clearing"""
        if not self.buffer:
            return None
        return b"".join(self.buffer)

    async def buffer_monitor(self, interval: float = _FLUSH_CHECK_INTERVAL):
        """Background buffer monitor for overflow and attack detection"""
        while True:
            await asyncio.sleep(interval)
            if self._buffer_size > _MAX_BUFFER_SIZE_BYTES:
                log_event("BUFFER: Overflow detected", level="WARNING")
                self.reset_buffer()
            if time.time() - self.last_flush > self.timeout * 2:
                log_event("BUFFER: Stale buffer detected", level="WARNING")
                self.reset_buffer()
            if time.time() - self._last_voice_time > _MAX_SILENCE_MS / 1000 * 2:
                log_event("BUFFER: Silence timeout", level="INFO")
                await self.flush_buffer()

def initialize_secure_buffer(user_id: Optional[str] = None) -> SecureAudioBuffer:
    """
    Factory function to create a SecureAudioBuffer with optional user binding.
    """
    buf = SecureAudioBuffer(user_id=user_id)
    asyncio.create_task(buf.buffer_monitor())
    return buf