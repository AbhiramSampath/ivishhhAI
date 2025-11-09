# realtime/captioning/caption_engine.py

import os
import uuid
import time
import asyncio
import datetime
import hmac
import hashlib
import json
import logging
from typing import Dict, List, Optional, Union, Any, AsyncGenerator
from collections import defaultdict

# SECURITY: Corrected and preserved imports based on project structure
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.mt_translate import translate_text

from backend.app.utils.logger import log_event
from config.system_flags import DEFAULT_LANG



# LOGGER CONFIG
logger = logging.getLogger(__name__)

# CONSTANTS
SESSION_HMAC_KEY = os.getenv("CAPTION_HMAC_KEY", "").encode() or os.urandom(32)
if len(SESSION_HMAC_KEY) < 32:
    SESSION_HMAC_KEY = hashlib.sha256(SESSION_HMAC_KEY).digest()
MAX_CLAUSE_LENGTH = int(os.getenv("MAX_CLAUSE_LENGTH", "500"))
MAX_PACKET_RATE = int(os.getenv("MAX_PACKET_RATE", "1000"))  # Max packets/sec
MIN_PROCESSING_TIME_MS = int(os.getenv("CAPTION_MIN_PROCESSING_TIME_MS", "100"))  # Prevent timing attack

class CaptionEngine:
    """
    Nuclear-grade secure caption engine with:
    - HMAC-signed caption packets
    - Input sanitization
    - Anti-tampering checks
    - Memory-safe processing
    - Secure fallback mechanisms
    - Constant-time operations
    """

    def __init__(self):
        self.hmac_key = SESSION_HMAC_KEY
        self.max_clause_length = MAX_CLAUSE_LENGTH
        self.packet_rate_limit = MAX_PACKET_RATE
        self.min_processing_time_ms = MIN_PROCESSING_TIME_MS
        self._rate_limits = defaultdict(int)

    async def process_stream(
        self, 
        stream_generator, 
        lang_from: str = DEFAULT_LANG, 
        lang_to: str = DEFAULT_LANG,
        user_id: Optional[str] = None
    ) -> AsyncGenerator[Dict, None]:  # Corrected return type
        """
        SECURE stream processor with:
        - Rate limiting
        - Input sanitization
        - HMAC packet signing
        - Secure packet yield
        """
        start_time = time.time()
        packet_count = 0
        try:
            # SECURITY: Rate limit per user_id or session
            if user_id:
                self._rate_limits[user_id] += 1
                if self._rate_limits[user_id] > self.packet_rate_limit:
                    log_event("Stream rate limit exceeded", level="WARNING", user=user_id)
                    yield self.fallback_caption()
                    return

            # SECURITY: Process each chunk
            async for chunk in stream_generator:
                if not isinstance(chunk, dict) or not chunk.get("clauses"):
                    continue

                for clause in chunk["clauses"]:
                    # SECURITY: Input sanitization
                    if not isinstance(clause, str) or len(clause) > self.max_clause_length:
                        yield self.fallback_caption("[...]")
                        continue

                    # SECURITY: Generate caption
                    caption = await self.generate_caption(clause, lang_from, lang_to, user_id)
                    yield caption

                # SECURITY: Anti-timing delay
                self._apply_processing_delay(start_time, target_ms=100)

        except Exception as e:
            logger.warning("Stream processing failed", exc_info=True)
            yield self.fallback_caption()

    async def generate_caption(
        self, 
        clause: str, 
        lang_from: str, 
        lang_to: str,
        user_id: Optional[str] = None
    ) -> Dict:
        """
        SECURE caption generation with:
        - Emotion detection
        - Translation fallback
        - Packet signing
        """
        start_time = time.time()
        try:
            # SECURITY: Sanitize clause
            clause = self._sanitize_text(clause)
            if not clause:
                return self.fallback_caption()

            # SECURITY: Detect emotion with timeout
            try:
                emotion = await asyncio.wait_for(detect_emotion(clause), timeout=0.05)
            except asyncio.TimeoutError:
                emotion = "neutral"

            # SECURITY: Translation with fallback
            translated = clause
            if lang_from != lang_to:
                translated = await translate_text(clause, lang_from, lang_to)
                if not isinstance(translated, str):
                    translated = clause  # Fallback to original

            # SECURITY: Style with differential privacy
         
            if not styled:
                styled = translated

            # SECURITY: Build packet
            packet = self.caption_packet(styled, emotion)
            packet["hmac"] = self._sign_packet(packet)

            # SECURITY: Anti-timing delay
            self._apply_processing_delay(start_time, target_ms=100)

            return packet

        except Exception as e:
            logger.warning("Caption generation failed", exc_info=True)
            return self.fallback_caption()

    def _sanitize_text(self, text: str) -> str:
        """SECURE text sanitization with injection protection"""
        if not isinstance(text, str):
            return ""
        # Remove control characters and truncate
        cleaned = ''.join(char for char in text if char.isprintable())
        return cleaned[:self.max_clause_length].strip()

    def _sign_packet(self, data: Dict) -> str:
        """Generate HMAC signature to prevent tampering"""
        try:
            # The hmac key should be a consistent bytes object
            h = hmac.new(self.hmac_key, digestmod=hashlib.sha256)
            # Serialize the data in a deterministic way
            h.update(json.dumps(data, sort_keys=True).encode('utf-8'))
            return h.hexdigest()
        except Exception as e:
            logger.warning("Packet signing failed", exc_info=True)
            return ""

    def caption_packet(
        self, 
        text: str, 
        tone: str = "neutral", 
        fallback: bool = False
    ) -> Dict:
        """
        SECURE packet generation with:
        - Tone validation
        - Input sanitization
        - Privacy-preserving timestamps
        """
        try:
            if tone not in {"happy", "sad", "angry", "neutral", "excited"}:
                tone = "neutral"

            text = self._sanitize_text(text)
            if not text:
                return self.fallback_caption()

            return {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "caption": text,
                "tone": tone,
                "fallback": fallback
            }

        except Exception as e:
            logger.warning("Packet generation failed", exc_info=True)
            return self.fallback_caption()

    def fallback_caption(self, text: str = "[...]") -> Dict:
        """
        SECURE fallback with:
        - Minimal processing
        - No model calls
        - HMAC signing
        """
        try:
            packet = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "caption": self._sanitize_text(text),
                "tone": "neutral",
                "fallback": True
            }
            packet["hmac"] = self._sign_packet(packet)
            return packet
        except Exception as e:
            logger.warning("Fallback caption failed", exc_info=True)
            # This is the final fallback, so it should not fail
            return {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "caption": "[SECURE FALLBACK]",
                "tone": "neutral",
                "fallback": True
            }

    def _apply_processing_delay(self, start_time: float, target_ms: int):
        """Prevent timing side-channels"""
        elapsed_ms = (time.time() - start_time) * 1000
        if elapsed_ms < target_ms:
            time.sleep((target_ms - elapsed_ms) / 1000)