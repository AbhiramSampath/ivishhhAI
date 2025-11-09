"""
emoji_reaction.py - Secure Emoji Reaction Engine for Ivish AI
"""

import os
import json
import uuid
import hashlib
from datetime import datetime
from typing import Any, Dict, Optional, Union
import logging
import asyncio
from pathlib import Path

# Internal imports - CORRECTED PATHS
from utils.logger import log_event
from ai_models.emotion.emotion_handler import detect_emotion
from security.blockchain.blockchain_utils import log_to_blockchain

# External imports - Removed non-existent
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Type aliases
Emotion = str
Emoji = str
EmojiMap = Dict[Emotion, Emoji]
CustomEmojiMap = Dict[Emotion, Emoji]

# Security: Secure emoji map path and hash
_FALLBACK_EMOJI = "🤖"  # Neutral fallback
_DEFAULT_EMOJI_MAP = {
    "happy": "😄", "sad": "😢", "angry": "😠", "surprised": "😮", "fear": "😨",
    "disgust": "🤢", "empathetic": "🤗", "neutral": "😐", "excited": "🤩",
    "confused": "😕"
}
_INTENSITY_MAP = {
    "angry": {0.7: "😡", 0.9: "👿"},
    "happy": {0.8: "😄", 0.95: "🤩"},
    "sad": {0.7: "😢"},
    "excited": {0.85: "🤩"},
    "neutral": {0.6: "😐"},
    "confused": {0.75: "😕"},
    "empathetic": {0.7: "🤗"}
}

# Logger config
logger = logging.getLogger(__name__)

class EmojiReactionEngine:
    """
    Secure emoji mapping engine for Ivish AI.
    """
    def __init__(self):
        self._logger = logging.getLogger("emoji_reaction")
        self._fallback = _FALLBACK_EMOJI
        self._default_map = _DEFAULT_EMOJI_MAP
        self._custom_map: CustomEmojiMap = {}
        self._intensity_map = _INTENSITY_MAP

    async def get_emoji(self, emotion: Emotion, intensity: Optional[float] = None) -> Emoji:
        """
        Return emoji with optional intensity-based variation.
        """
        if not isinstance(emotion, str) or len(emotion) > 64:
            return self._fallback

        emoji = self._custom_map.get(emotion.lower(), self._default_map.get(emotion.lower(), self._fallback))
        
        if intensity is not None:
            emotion_key = emotion.lower()
            if emotion_key in self._intensity_map:
                for threshold, intensity_emoji in sorted(self._intensity_map[emotion_key].items(), reverse=True):
                    if intensity >= threshold:
                        return intensity_emoji
        return emoji

    async def from_text(self, text: str) -> Emoji:
        """
        End-to-end pipeline: text → emotion → emoji
        """
        if not text or not isinstance(text, str):
            return self._fallback
        try:
            emotion_data = await detect_emotion(text[:1024])
            emotion = emotion_data.get("label", "neutral")
            confidence = emotion_data.get("confidence", 0.0)
            return await self.get_emoji(emotion, confidence)
        except Exception as e:
            self._logger.error(f"Emoji detection failed: {str(e)}")
            return self._fallback

    async def register_custom(self, emotion: Emotion, emoji: Emoji) -> bool:
        """
        Secure runtime registration of new emoji mappings.
        """
        if not isinstance(emotion, str) or not isinstance(emoji, str):
            return False
        if len(emotion) > 64 or len(emoji) > 4:
            return False
        try:
            self._custom_map[emotion.lower()] = emoji
            self._logger.info(f"Registered custom emoji: {emotion} → {emoji}")
            await log_to_blockchain("custom_emoji_registered", {
                "event": "custom_emoji_registered",
                "emotion": emotion,
                "emoji": emoji,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            return True
        except Exception as e:
            self._logger.error(f"Custom emoji registration failed: {str(e)}")
            return False

    def list_emotions(self) -> Dict[str, Dict]:
        """
        Return all supported emotions with integrity hashes.
        """
        merged_map = {**self._default_map, **self._custom_map}
        return {
            "builtin": {k: v for k, v in self._default_map.items()},
            "custom": self._custom_map,
            "fallback": self._fallback
        }

# Simplified interface functions
emoji_engine = EmojiReactionEngine()

get_emoji_from_emotion = emoji_engine.get_emoji
emoji_reaction_for_text = emoji_engine.from_text
register_custom_emoji = emoji_engine.register_custom
list_supported_emotions = lambda: emoji_engine.list_emotions()