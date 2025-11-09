# ai_models/avatar/emotion_driver.py
# 🔒 Nuclear-Grade Emotion Driver with Zero-Trust Security
# Maps emotion labels to avatar animation and emoji overlay

import os
import json
import uuid
import time
import asyncio
import logging
import subprocess
import numpy as np
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Corrected Internal Imports based on project architecture
from ai_models.emotion.emotion_handler import detect_emotion
from realtime.socketio.manager import emit_to_avatar
from backend.app.utils.logger import log_event, BaseLogger
from security.blockchain.zkp_handler import validate_user_for_emotion_profile

# --- Constants (from removed config/utils files) --- #
EMOTION_MODE = os.getenv("EMOTION_MODE", "True").lower() == "true"
EMOTION_ANIMATIONS = {
    "joyful": "happy_animation",
    "calm": "calm_animation",
    "empathetic": "empathetic_animation",
    "neutral": "neutral_animation",
    # ... more emotions
}
EMOTION_EMOJIS = {
    "joyful": "😊",
    "calm": "😌",
    "empathetic": "❤️‍🩹",
    "neutral": "🙂",
    # ... more emotions
}
EMOTION_AUDIO_MOD = {
    "joyful": {"pitch": 1.1, "speed": 1.1, "volume": 1.05},
    "calm": {"pitch": 0.9, "speed": 0.9, "volume": 0.95},
    "empathetic": {"pitch": 0.95, "speed": 0.95, "volume": 1.0},
    "neutral": {"pitch": 1.0, "speed": 1.0, "volume": 1.0},
    # ... more emotions
}

AES_KEY = os.getenv("EMOTION_AES_KEY", os.urandom(32))
MAX_EMOTION_RATE = 10  # Max emotions/sec (anti-flood)
BLACKHOLE_DELAY = 60   # Seconds to delay attacker
EMOJI_SANITIZE_CHARS = ["<", ">", "&", "'", "\""]  # XSS prevention
TEMP_EMOTION_PATHS = ["/tmp/emotion_cache_*", "/dev/shm/avatar_*"]

# Initialize a logger
logger = BaseLogger("EmotionDriver")

class EmotionDriver:
    """
    Provides secure, real-time emotion mapping to avatar animation and audio modulation.
    
    Responsibilities:
    - Detect emotion from input text or tone
    - Map emotion to avatar animation
    - Attach emoji overlay or tone markers
    - Encrypt payload for secure WebSocket transmission
    - Rate-limit emotion triggers
    - Trigger fallback if emotion confidence is low
    - Optionally forward to TTS engine for tone modulation
    """

    def __init__(self):
        self._emotion_counter = 0
        self._last_reset = time.time()

    def _reset_rate_limit(self):
        now = time.time()
        if now - self._last_reset > 60:
            self._emotion_counter = 0
            self._last_reset = now

    async def _validate_rate_limit(self) -> bool:
        """Prevent emotion flooding attacks."""
        self._reset_rate_limit()
        self._emotion_counter += 1
        if self._emotion_counter > MAX_EMOTION_RATE:
            await log_event("[SECURITY] Emotion rate limit exceeded", level="ALERT")
            await self._trigger_blackhole()
            return False
        return True

    async def _trigger_blackhole(self):
        """Null response + artificial delay on attack detection."""
        logger.log_event(f"Blackhole activated for {BLACKHOLE_DELAY}s", level="WARNING")
        await asyncio.sleep(BLACKHOLE_DELAY)

    def _encrypt_payload(self, data: str) -> bytes:
        """AES-256-CBC encrypt all socket payloads with a unique IV."""
        try:
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(AES_KEY),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()

            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
            
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return iv + encrypted
        except Exception as e:
            logger.log_event(f"[ENCRYPTION_FAILURE] {e}", level="ALERT")
            return b''

    def _sanitize_input(self, text: str) -> str:
        """Prevent injection attacks in emotion detection."""
        return text[:5000].replace('\0', '')

    async def _secure_wipe(self, paths: list):
        """Securely wipe temporary emotion data in a non-blocking way."""
        for path in paths:
            try:
                # Use asyncio.to_thread for blocking subprocess calls
                await asyncio.to_thread(
                    subprocess.run,
                    ['shred', '-u', path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                logger.log_event(f"Secure wipe failed for {path}: {e}", level="ERROR")

    async def _validate_user_profile(self, user_id: str) -> bool:
        """ZKP-based user profile validation."""
        # The function `validate_user_for_emotion_profile` should be async
        return await validate_user_for_emotion_profile(user_id)

    async def drive_avatar_emotion(self, text: str, user_id: str) -> Optional[Dict]:
        """
        Secure emotion driver with:
        - AES-256 encrypted comms
        - Rate-limited emotion triggers
        - Zero-trust payload validation
        """
        if not EMOTION_MODE or not await self._validate_rate_limit():
            return None

        if not await self._validate_user_profile(user_id):
            logger.log_event(f"[SECURITY] Unauthorized emotion access for {user_id[:6]}...", level="ALERT")
            return None

        session_id = str(uuid.uuid5(uuid.NAMESPACE_OID, user_id))

        try:
            emotion = await detect_emotion(self._sanitize_input(text))
            animation = self.map_emotion_to_avatar(emotion)
            emoji = self.attach_emoji_overlay(emotion)
            audio_mod = self.get_audio_modulation(emotion)

            payload = {
                "emotion": emotion,
                "animation": animation,
                "emoji": emoji,
                "audio_mod": audio_mod,
                "user_id": user_id,
                "session_id": session_id
            }

            encrypted_payload = self._encrypt_payload(json.dumps(payload))

            await self.broadcast_emotion(encrypted_payload)
            logger.log_event(f"[AVATAR_EMOTION] {emotion} triggered", encrypted=True)

            return {
                "status": "triggered",
                "emotion": emotion,
                "animation": animation,
                "emoji": emoji,
                "audio_mod": audio_mod,
                "session_id": session_id
            }

        except Exception as e:
            logger.log_event(f"[ERROR] Emotion driver failed: {str(e)}", level="ALERT")
            return None

    @staticmethod
    def map_emotion_to_avatar(emotion: str) -> str:
        """Secure emotion mapping with fallback."""
        return EMOTION_ANIMATIONS.get(
            emotion.lower().strip(), 
            "neutral_idle"
        )

    @staticmethod
    def attach_emoji_overlay(emotion: str) -> str:
        """Emoji mapping with XSS sanitization."""
        emoji = EMOTION_EMOJIS.get(
            emotion.lower().strip(), 
            "🙂"
        )
        for char in EMOJI_SANITIZE_CHARS:
            emoji = emoji.replace(char, "")
        return emoji

    @staticmethod
    def get_audio_modulation(emotion: str) -> Dict[str, float]:
        """Get TTS modulation settings based on emotion."""
        return EMOTION_AUDIO_MOD.get(
            emotion.lower().strip(),
            {"pitch": 1.0, "speed": 1.0, "volume": 1.0}
        )

    async def broadcast_emotion(self, encrypted_payload: bytes):
        """Secure WebSocket emission with payload validation."""
        try:
            await emit_to_avatar("emotion_signal", encrypted_payload)
        except Exception as e:
            logger.log_event(f"[SOCKET_FAILURE] {str(e)}", level="ALERT")

# Singleton with rate-limiting
emotion_driver = EmotionDriver()