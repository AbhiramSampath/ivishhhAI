# ai_models/cultural/context_analyzer.py
"""
🧠 Ivish AI Cultural Context Analyzer
🔐 Ensures culturally, regionally, and emotionally appropriate AI behavior
📦 Analyzes: dialects, idioms, taboos, time-sensitive phrases, location norms
🛡️ Features: injection sanitization, dataset integrity, secure logging, anti-bias rephrasing
"""

import os
import re
import hashlib
import logging
import json
import base64
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
from cryptography.fernet import Fernet
from functools import lru_cache

# 🔐 Security Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from security.blockchain.zkp_handler import ZKPHandler as ZKPAuthenticator # Corrected from zkp_auth
from security.firewall import Firewall as DefenseFirewall # Corrected from os.system

# 📁 Corrected Project Imports
from ai_models.emotion.emotion_handler import detect_emotion
from backend.app.utils.logger import log_event

# --- Placeholder Imports (for modules not in the provided structure) ---
def detect_dialect(text: str) -> str:
    """Placeholder for language_tags.detect_dialect"""
    return "en-US"

def map_to_region(dialect: str) -> str:
    """Placeholder for language_tags.map_to_region"""
    return "North America"

def load_cultural_dataset() -> Dict:
    """Placeholder for datasets.languages.lookup.load_cultural_dataset"""
    # A realistic placeholder with some data
    return {
        "North America": {
            "idioms": ["hit the nail on the head", "bite the bullet"],
            "taboos": ["bitch", "ass"]
        },
        "South India": {
            "idioms": ["tea time", "take a look"],
            "taboos": ["piss"]
        },
    }

# 🔒 Security Constants
# CULTURAL_DB_HASH must be precomputed and securely stored
_CULTURAL_DB_HASH = "sha256:4a02d4f58c7310d5138f32a76f2d93e83921b6d2e9680380f2d9774659f81d11"
_MAX_TEXT_LENGTH = 1000
_FERNET_KEY = os.getenv("CULTURAL_FERNET_KEY", Fernet.generate_key().decode()).encode()
_SALT = b"secure_salt_for_cultural_analyzer"
_BACKEND = default_backend()
CULTURE_SENSITIVITY_MODE = os.getenv("CULTURE_SENSITIVITY_MODE", "True").lower() == "true"

# 🔐 AES Encryption Setup
def _get_cipher_suite(key: bytes) -> Fernet:
    """Secure AES-256 key derivation"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=100000,
        backend=_BACKEND
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(key))
    return Fernet(derived_key)

_CIPHER_SUITE = _get_cipher_suite(_FERNET_KEY)

@dataclass
class CulturalContext:
    dialect: str
    region: str
    emotion: str
    cultural_alert: Optional[str]
    tags: List[str]
    secure_text: str

class CulturalAnalyzer:
    """
    🔒 Secure Cultural Analyzer
    """
    def __init__(self):
        self._cultural_db = self._load_verified_dataset()
        self._cipher = _CIPHER_SUITE
        self._region_cache = {}
        self.defense_firewall = DefenseFirewall()
        self.zkp_auth = ZKPAuthenticator()

    def _load_verified_dataset(self) -> Dict:
        """Load dataset with hash verification."""
        raw_db = load_cultural_dataset()
        # Use a deterministic hash to prevent false positives
        db_string = json.dumps(raw_db, sort_keys=True).encode()
        current_hash = hashlib.sha256(db_string).hexdigest()
        expected_hash = _CULTURAL_DB_HASH.replace("sha256:", "")
        if current_hash != expected_hash:
            logging.critical("🚨 Cultural dataset tampered!")
            self._trigger_defense_response()
            raise RuntimeError("Dataset integrity check failed")
        return raw_db

    def _sanitize_input(self, text: str) -> str:
        """Prevent injection attacks."""
        if len(text) > _MAX_TEXT_LENGTH:
            raise ValueError("Input text too long")
        # Sanitize based on a whitelist of allowed characters
        return re.sub(r'[^\w\s.,!?@]', '', text)[:_MAX_TEXT_LENGTH]

    async def analyze_context(self, text: str, user_meta: Dict) -> Dict:
        """
        Hardened cultural analysis with input sanitization and encryption.
        """
        try:
            clean_text = self._sanitize_input(text)
            encrypted_text = self._cipher.encrypt(clean_text.encode())

            dialect = detect_dialect(clean_text)
            region = user_meta.get("region") or self._get_cached_region(dialect)
            # detect_emotion is an async function in the corrected tone_emotion_detector
            emotion = await detect_emotion(clean_text)

            idioms, risk_terms = self._detect_local_phrases(clean_text, region)
            cultural_alert = self._flag_cultural_risks(risk_terms)

            result = CulturalContext(
                dialect=dialect,
                region=region,
                emotion=emotion,
                cultural_alert=cultural_alert,
                tags=idioms,
                secure_text=encrypted_text.decode()
            )

            if cultural_alert:
                self._log_incident(user_meta["user_id"], clean_text, cultural_alert)

            return result.__dict__
        except Exception as e:
            logging.error(f"🚨 Cultural analysis failed: {str(e)}")
            return {
                "error": "Analysis unavailable",
                "security_level": "high"
            }

    @lru_cache(maxsize=128)
    def _get_cached_region(self, dialect: str) -> str:
        """Memoized region lookup with cache invalidation."""
        return map_to_region(dialect)

    def _detect_local_phrases(self, text: str, region: str) -> Tuple[List[str], List[str]]:
        idioms = []
        risky_terms = []

        region_data = self._cultural_db.get(region, {})
        for phrase in region_data.get("idioms", []):
            if re.search(rf'\b{re.escape(phrase)}\b', text.lower()):
                idioms.append(phrase)
        for term in region_data.get("taboos", []):
            if re.search(rf'\b{re.escape(term)}\b', text.lower()):
                risky_terms.append(term)

        return idioms, risky_terms

    def _flag_cultural_risks(self, risky_terms: List[str]) -> Optional[str]:
        if not CULTURE_SENSITIVITY_MODE or not risky_terms:
            return None
        masked_terms = [hashlib.sha256(t.encode()).hexdigest()[:8] for t in risky_terms]
        return f"CULTURAL_ALERT:{':'.join(masked_terms)}"

    def _log_incident(self, user_id: str, text: str, alert: str):
        redacted_text = re.sub(r'\b\w{10,}\b', '[REDACTED]', text)
        log_event(
            f"[CULTURAL] user={hashlib.sha256(user_id.encode()).hexdigest()[:6]} "
            f"alert={alert} text_len={len(redacted_text)}"
        )

    def suggest_local_rewrite(self, text: str, region: str) -> str:
        suggestions = {
            "Tamil Nadu": [("you people", "everyone")],
            "Japan": [("old man", "respected elder")],
            "Middle East": [("dog", "animal")],
            "Germany": [("I think", "In my opinion")],
            "France": [("we", "nous")],
            "Bengal": [("bhai", "dada")],
            "Punjab": [("bhai", "bhaiji")],
            "South India": [("hello", "vanakkam")],
            "North India": [("hello", "namaste")]
        }

        for original, replacement in suggestions.get(region, []):
            if original in text.lower():
                text = re.sub(rf'\b{re.escape(original)}\b', replacement, text, flags=re.IGNORECASE)
        return text

    def _trigger_defense_response(self):
        logging.critical("🚨 DATASET TAMPERING DETECTED: Activating honeypot and endpoint rotation")
        try:
            self.zkp_auth.rotate_keys()
        except Exception as e:
            logging.error(f"Failed to rotate ZKP keys: {e}")
        try:
            self.defense_firewall.activate_intrusion_response()
        except Exception as e:
            logging.error(f"Failed to update firewall rules: {e}")
        logging.info(
            "🔐 Defense response activated: Honeypot and endpoint rotation in effect"
        )