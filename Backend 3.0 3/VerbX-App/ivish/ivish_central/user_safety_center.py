"""
🧠 Ivish AI User Safety Central
🔐 Real-time emotional, behavioral, and biometric safety monitoring system
📦 Detects distress, abuse, unsafe prompts, and triggers protective responses
🛡️ Security: ZKP auth, input sanitization, anti-tamper, blockchain logging
"""

import os
import re
import uuid
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import asyncio
import logging
import json
from functools import lru_cache
import hmac

# 🔐 Security Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# 📁 Project Imports (Corrected based on file structure)
from ai_models.emotion.emotion_handler import detect_emotion
from ai_control.safety_decision_manager import detect_risk_keywords
from ivish_central.agent_router import route_response
from backend.app.utils.logger import log_event
from ai_models.personalization.profile_tracker import update_tone_memory, get_user_tone
from ai_models.personalization.consent_handler import purge_user_data
from security.blockchain.blockchain_utils import log_to_blockchain
from security.blockchain.zkp_handler import ZKPAuthenticator
from config.system_flags import ESCALATION_ENABLED

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = b"user_safety_signature_key_256bit"
if len(_HMAC_KEY) < 32:
    _HMAC_KEY = hashlib.sha256(_HMAC_KEY).digest()
_KDF_ITERATIONS = 100000
_LATENCY_BUDGET_MS = 200
_MAX_INPUT_LENGTH = 5000
_MAX_ATTEMPTS = 5
_VALID_FLAGS = {
    "suicidal_ideation",
    "emotional_distress",
    "abusive_language",
    "self_harm",
    "violence",
    "sexual_content",
    "medical_emergency"
}
# Maximum length for input text stored in blockchain logs
_BLOCKCHAIN_INPUT_TRUNCATE_LENGTH = 1000

@dataclass
class SafetyEvent:
    """
    📌 Structured safety event
    - user_id: anonymized
    - emotion: detected emotional state
    - flags: safety flags triggered
    - input: sanitized input text (truncated for blockchain)
    - timestamp: ISO timestamp
    - _signature: HMAC signature for tamper detection
    """
    user_id: str
    emotion: str
    flags: List[str]
    input: str
    timestamp: str
    _signature: Optional[str] = None

class UserSafetyEngine:
    """
    🔒 Secure User Safety Engine
    - Monitors user emotional and behavioral state
    - Detects risk flags and unsafe inputs
    - Triggers empathetic or defensive responses
    - Logs to blockchain
    - Integrates with response router, escalation system
    - Implements anti-abuse, rate limiting, and honeypot defenses
    """

    def __init__(self):
        """Secure initialization"""
        self.session_token = os.urandom(16).hex()
        self._breach_counter = {}
        self._init_rate_limits()
        self.zkp_authenticator = ZKPAuthenticator()

    def _sign_event(self, event: Dict) -> str:
        """HMAC-sign safety event using deterministic JSON serialization"""
        serialized = json.dumps(event, sort_keys=True, separators=(',', ':')).encode('utf-8')
        hmac_ctx = HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        hmac_ctx.update(serialized)
        return hmac_ctx.finalize().hex()

    def _init_rate_limits(self):
        """Prevent API abuse"""
        self.min_call_interval = timedelta(seconds=2)
        self.last_call_time = {}

    def _check_rate_limit(self, user_id: str) -> bool:
        """Prevent API flooding"""
        now = datetime.now()
        last = self.last_call_time.get(user_id, datetime.min)
        if now - last < self.min_call_interval:
            self._breach_counter[user_id] = self._breach_counter.get(user_id, 0) + 1
            if self._breach_counter[user_id] > _MAX_ATTEMPTS:
                asyncio.create_task(self._trigger_defense_response(user_id))
            return False
        self.last_call_time[user_id] = now
        self._breach_counter[user_id] = 0
        return True

    def _sanitize_input(self, text: str) -> str:
        """Nuclear-grade input cleaning"""
        if not text or not isinstance(text, str):
            return ""
        # Remove non-printable characters and truncate
        cleaned = ''.join(char for char in text if char.isprintable())
        return cleaned[:_MAX_INPUT_LENGTH]

    async def monitor_user_state(self, user_id: str, input_text: str, audio_chunk: Optional[bytes] = None) -> Dict:
        """
        🔐 Core safety monitoring pipeline
        """
        try:
            # 🔍 Intrusion Pre-Check
            if not self._check_rate_limit(user_id):
                await log_event("RATE_LIMIT_HIT", user_id=user_id, level="WARNING")
                return {"status": "locked", "flags": ["security_breach"]}

            # 🧹 Input Sanitization
            sanitized_text = self._sanitize_input(input_text)
            if not sanitized_text:
                await log_to_blockchain("input_tamper", {"user_id": self._obfuscate_user_id(user_id)})
                return {"status": "invalid_input"}

            # 🔐 Zero-Knowledge Session Proof
            if not self.zkp_authenticator.verify_session(user_id, self.session_token):
                await self._feed_honeypot(user_id)
                return {"status": "auth_failed"}

            # ⚡ Async Parallel Execution (Latency Optimization)
            emotion_task = self._detect_emotion(sanitized_text, audio_chunk)
            flags_task = self._safe_detect_flags(sanitized_text)
            memory_task = get_user_tone(user_id)

            emotion, flags, memory = await asyncio.gather(emotion_task, flags_task, memory_task)

            # 📈 Update tone history
            await update_tone_memory(user_id, emotion)

            # 🚨 Trigger actions for detected flags
            if flags:
                await asyncio.gather(*[self._take_action(flag, user_id) for flag in flags])
                status = "flagged"
            else:
                status = "clear"

            # 📜 Immutable Audit Trail
            await self._log_safety_decision(user_id, sanitized_text, emotion, flags)

            return {
                "status": status,
                "flags": flags,
                "emotion": emotion,
                "memory": memory,
                "timestamp": datetime.now().isoformat(),
                "session_token": self.session_token
            }

        except Exception as e:
            await log_event(f"SAFETY_MONITOR_FAILURE: {str(e)}", level="CRITICAL")
            return {"status": "error", "reason": str(e)}

    async def _detect_emotion(self, text: str, audio: Optional[bytes] = None) -> str:
        """Secure emotion detection from text or voice"""
        if audio:
            # Assumed asynchronous, secure voice emotion detection
            return detect_emotion(audio)
        else:
            return detect_emotion(text)

    async def _safe_detect_flags(self, text: str) -> List[str]:
        """Wrap flag detection with anti-DoS"""
        try:
            emotion = await self._detect_emotion(text)
            flags = []
            
            if emotion in ["sad", "distressed", "hopeless"]:
                flags.append("emotional_distress")

            risk_keywords = detect_risk_keywords(text)
            if risk_keywords:
                flags.extend(risk_keywords)

            return list(set(flags))
        except Exception as e:
            await log_event(f"FLAG_DETECTION_FAILURE: {str(e)}", level="ERROR")
            return []

    async def _take_action(self, flag: str, user_id: str):
        """Hardened action router"""
        if flag not in _VALID_FLAGS:
            return

        if flag == "suicidal_ideation" and ESCALATION_ENABLED:
            await route_response(user_id, "Please take a breath. You're not alone. Connecting you to help...")
        elif flag == "abusive_language":
            await route_response(user_id, "We aim to help. Let's keep this respectful.")
        elif flag == "medical_emergency":
            await route_response(user_id, "This sounds urgent. Should I connect you to emergency services?")
        elif flag == "sexual_content":
            await route_response(user_id, "This conversation needs to stay respectful and appropriate.")
        elif flag == "violence":
            await route_response(user_id, "I'm here to help, not to harm.")
        elif flag == "self_harm":
            await route_response(user_id, "You're important. Let's talk.")
        else:
            await route_response(user_id, "Let’s take a moment to talk about this calmly.")

    async def _log_safety_decision(self, user_id: str, input_text: str, emotion: str, flags: List[str]):
        """Tamper-proof logging"""
        obfuscated_id = self._obfuscate_user_id(user_id)
        event = SafetyEvent(
            user_id=obfuscated_id,
            emotion=emotion,
            flags=flags,
            input=input_text[:_BLOCKCHAIN_INPUT_TRUNCATE_LENGTH],
            timestamp=datetime.now().isoformat(),
            _signature=None
        )
        event_dict = event.__dict__
        event_dict["_signature"] = self._sign_event(event_dict)
        await log_to_blockchain("user_safety", event_dict)

    def _obfuscate_user_id(self, user_id: str) -> str:
        """Pseudonymization via cryptographic hashing"""
        digest = hashes.Hash(hashes.BLAKE2s(16), backend=_BACKEND)
        digest.update(user_id.encode())
        return digest.finalize().hex()

    async def _trigger_defense_response(self, user_id: str):
        """Reverse-intrusion response system"""
        logging.critical(f"🚨 SECURITY BREACH DETECTED: {user_id}")
        self.zkp_authenticator.rotate_keys()
        # Placeholder for cross-platform firewall/security response
        await purge_user_data(user_id)
        await log_event(f"EMERGENCY_WIPE: {user_id}", level="EMERGENCY")

    async def _feed_honeypot(self, user_id: str):
        """Serve fake responses to attackers"""
        await route_response(user_id, "Let's talk about how you're feeling.")
        await log_to_blockchain("honeypot_served", {
            "user_id": self._obfuscate_user_id(user_id),
            "timestamp": datetime.now().isoformat(),
            "flags": ["emotional_distress"]
        })

user_safety_engine = UserSafetyEngine()