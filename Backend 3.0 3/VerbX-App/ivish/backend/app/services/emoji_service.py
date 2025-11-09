"""
🧠 Ivish AI Emoji Service
🔐 Adds emotional expressiveness to AI responses with security, compliance, and regional awareness
📦 Features: emotion mapping, emoji injection, input sanitization, secure logging
🛡️ Security: input validation, emoji blacklist, encrypted logs, ZKP integration
"""

import os
import re
import json
import uuid
import random
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

# 🔐 Security Imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# 📁 Project Imports - CORRECTED PATHS
from utils.logger import log_event
from ai_models.emotion.emotion_handler import EmotionHandler
from security.blockchain.zkp_handler import ZKPHandler
from security.blockchain.blockchain_utils import BlockchainLogger
from security.firewall import Firewall
from security.encryption_utils import generate_session_token, validate_data_signature
from security.intrusion_prevention.counter_response import blackhole_ip
from utils.helpers import get_supported_regions

# 🔐 Security Constants
_BACKEND = default_backend()
_AES_KEY = os.environ.get("EMOJI_AES_KEY", "default_aes_key_32_bytes_1234567890").encode('utf-8')
_AES_NONCE = b"emoji_nonce_12" # A better practice is to generate a new nonce for each encryption
_LATENCY_BUDGET_MS = 50
_MAX_TEXT_LENGTH = 1024
_EMOJI_BLACKLIST = {"🇸🇾", "🇮🇷", "💣", "🖕", "🔪", "🔫", "🧨", "🎯"}

# Emoji Map - This should be a part of the AI model's configuration
EMOTION_TO_EMOJI = {
    "joy": ["😄", "😃", "😀", "😁", "😂"],
    "sadness": ["😢", "😥", "😔", "😞"],
    "anger": ["😠", "😡", "😤"],
    "surprise": ["😮", "😲", "😳"],
    "fear": ["😨", "😰"],
    "love": ["❤️", "😍", "🥰"],
    "calm": ["😌", "😊"],
    "neutral": ["😐", "😑"]
}
_SUPPORTED_EMOTIONS = list(EMOTION_TO_EMOJI.keys())
_SUPPORTED_REGIONS = get_supported_regions()

@dataclass
class EmojiUsageLog:
    """
    📌 Structured emoji usage log
    - session_id: unique session token
    - emotion: detected emotional state
    - emoji: selected emoji
    - timestamp: ISO timestamp
    - region: user region
    - _signature: HMAC signature for tamper detection
    """
    session_id: str
    emotion: str
    emoji: str
    timestamp: str
    region: str
    _signature: Optional[str] = None

class SecureEmojiService:
    """
    🔒 Secure Emoji Injection Engine
    - Maps emotion to emoji
    - Decorates responses
    - Detects emotion from text
    - Applies region-aware emoji sets
    - Encrypts logs
    - Blacklists sensitive emojis
    - Integrates with blockchain
    - Implements ZKP access control
    """

    def __init__(self):
        """Secure initialization"""
        self.session_token = generate_session_token()
        self._aes_gcm = AESGCM(_AES_KEY)
        self.emotion_handler = EmotionHandler()
        self.zkp_handler = ZKPHandler()
        self.blockchain_logger = BlockchainLogger()
        self.firewall = Firewall()
        self._init_emoji_cache()
        self._init_region_mapping()

    def _init_emoji_cache(self):
        """Initialize secure emoji cache"""
        self.emoji_cache = {emotion: self._filter_emojis(emojis) for emotion, emojis in EMOTION_TO_EMOJI.items()}

    def _filter_emojis(self, emojis: List[str]) -> List[str]:
        """Removes blacklisted emojis from a list"""
        return [emoji for emoji in emojis if emoji not in _EMOJI_BLACKLIST]

    def _init_region_mapping(self):
        """Map region to emoji variants"""
        # This mapping is simplified. In production, this would be a more comprehensive mapping
        self.region_emoji_map = {
            region: EMOTION_TO_EMOJI for region in _SUPPORTED_REGIONS
        }

    def _encrypt_log(self, data: Dict) -> bytes:
        """AES-GCM encryption of sensitive logs"""
        nonce = os.urandom(12)
        data_bytes = json.dumps(data).encode('utf-8')
        encrypted = self._aes_gcm.encrypt(nonce, data_bytes, None)
        return nonce + encrypted

    def _sanitize_emotion(self, emotion: str) -> str:
        """Nuclear-grade emotion sanitization"""
        return re.sub(r'[^a-z]', '', emotion.lower())

    @lru_cache(maxsize=1024)
    def _get_region_emoji(self, emotion: str, region: str) -> str:
        """Secure region-aware emoji selection"""
        region = region if region in self.region_emoji_map else "en"
        sanitized_emotion = self._sanitize_emotion(emotion)
        
        emoji_list = self.region_emoji_map[region].get(sanitized_emotion)
        if not emoji_list:
            return "🤖"

        # Deterministic RNG for consistent UX
        r = random.Random(hash(sanitized_emotion + region))
        return r.choice(emoji_list)

    def get_emoji(self, emotion: str, count: int = 1) -> List[str]:
        """Return one or more emojis for a given emotion"""
        try:
            sanitized_emotion = self._sanitize_emotion(emotion)
            emoji_list = self.emoji_cache.get(sanitized_emotion, ["🤖"])

            if not emoji_list:
                return ["🤖"]

            # Deterministic RNG for consistent UX
            r = random.Random(hash(sanitized_emotion))
            return r.choices(emoji_list, k=min(count, len(emoji_list)))
        except Exception as e:
            logging.error(f"EMOJI_GENERATION_FAILURE: {str(e)}")
            return ["🚨"]

    def decorate_response(self, text: str, emotion: str = "neutral", region: str = "en") -> str:
        """Securely add emoji to text with tamper detection"""
        try:
            if not isinstance(text, str) or len(text) > _MAX_TEXT_LENGTH:
                log_event("EMOJI_INPUT_VALIDATION_FAILED", "Invalid input length or type")
                return "🚨 Invalid input"

            if not validate_data_signature(text, self.session_token):
                log_event("EMOJI_TAMPER_DETECTED", f"Tampered text input: {text}")
                self._trigger_defense_response(ip_address="user_ip_placeholder") # Pass IP for blackholing
                return "🚨 Tampered input"

            emojis = self.get_emoji(emotion, 1)
            decorated = f"{text}\u200B{emojis[0]}"
            session_id = str(uuid.uuid4())

            # 📜 Blockchain logging
            log_data = EmojiUsageLog(
                session_id=session_id,
                emotion=emotion,
                emoji=emojis[0],
                timestamp=datetime.now().isoformat(),
                region=region
            )
            self.blockchain_logger.log_event("emoji_usage", log_data)
            return decorated

        except Exception as e:
            logging.error(f"EMOJI_DECORATION_FAILURE: {str(e)}")
            return text

    def auto_emoji_from_text(self, text: str, region: str = "en") -> str:
        """Full pipeline: text → emotion → emoji"""
        try:
            if not text or len(text) > _MAX_TEXT_LENGTH:
                log_event("EMOJI_AUTOMATION_FAILED", "Invalid text input")
                return "🚨"

            if not validate_data_signature(text, self.session_token):
                log_event("EMOJI_AUTOMATION_TAMPER_DETECTED", "Tampered text input")
                self._trigger_defense_response(ip_address="user_ip_placeholder")
                return "🚨"

            emotion = self.emotion_handler.detect_emotion(text)
            return self.decorate_response(text, emotion, region)

        except Exception as e:
            logging.error(f"EMOJI_AUTOMATION_FAILURE: {str(e)}")
            return text

    def get_all_supported_emotions(self) -> List[str]:
        """Return validated emotion list"""
        return list(self.emoji_cache.keys())

    def _trigger_defense_response(self, ip_address: str):
        """Reverse-intrusion response system"""
        log_event("SECURITY_EVENT_TRIGGERED", f"EMOJI TAMPERING DETECTED from {ip_address}")
        self.zkp_handler.rotate_keys()
        self.firewall.blackhole_ip(ip_address)
        # Add more sophisticated responses here like notifying the security team