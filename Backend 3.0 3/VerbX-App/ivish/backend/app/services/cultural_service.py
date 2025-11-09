# backend/services/cultural_service.py
# 🔒 Final, Secure Cross-Cultural Sensitivity Engine
# 🚀 Refactored Code

import datetime
import os
import json
import hashlib
import hmac
import logging
import asyncio
from typing import Any, Dict, List, Optional, Union
from functools import lru_cache
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.constant_time import bytes_eq

# Corrected Internal imports
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.dialect_adapter import detect_language
from utils.logger import log_event
from utils.security import sanitize_prompt

# Type aliases
TextInput = str
LanguageCode = str
CulturalFlag = str
CulturalAnalysis = Dict[str, Any]

# Load keys from environment variables and fail if not present
CULTURAL_RULES_KEY = os.getenv("CULTURAL_RULES_KEY", None)
if not CULTURAL_RULES_KEY:
    raise RuntimeError("CULTURAL_RULES_KEY not found in environment.")

CULTURAL_HMAC_KEY = os.getenv("CULTURAL_HMAC_KEY", None)
if not CULTURAL_HMAC_KEY:
    raise RuntimeError("CULTURAL_HMAC_KEY not found in environment.")

logger = logging.getLogger("cultural_service")

class CulturalService:
    """
    Secure cultural sensitivity and etiquette engine for Ivish AI.
    """
    def __init__(self):
        self._fernet = Fernet(CULTURAL_RULES_KEY.encode())
        self._supported_languages = {"en", "hi", "ta", "te", "bn", "mr", "ur", "gu"} # Example list

    @lru_cache(maxsize=32)
    def _secure_load_rules(self, lang_code: LanguageCode) -> Dict:
        """
        Loads, decrypts, and verifies integrity of cultural rules.
        """
        if lang_code not in self._supported_languages:
            return {}

        file_path = os.path.join("datasets/cultural", f"rules_{lang_code}.json")
        if not os.path.exists(file_path):
            return {}

        with open(file_path, 'rb') as f:
            encrypted_data_hex = f.read().decode().strip()

        try:
            encrypted_data = bytes.fromhex(encrypted_data_hex)
            decrypted_data = self._fernet.decrypt(encrypted_data)
            rules = json.loads(decrypted_data)
            
            computed_hmac = hmac.HMAC(CULTURAL_HMAC_KEY.encode(), hashes.SHA256())
            computed_hmac.update(decrypted_data)
            
            if not bytes_eq(computed_hmac.finalize(), bytes.fromhex(rules.get('_integrity_hash', ''))):
                raise ValueError("Integrity hash mismatch")

            return rules
        except Exception as e:
            logger.critical(f"Cultural rules for '{lang_code}' tampering detected: {e}")
            return {}

    async def analyze_cultural_sensitivity(self, text: TextInput, lang_code: Optional[LanguageCode] = None) -> CulturalAnalysis:
        """
        Analyze text for cultural sensitivity.
        """
        if not isinstance(text, str) or len(text) > 1000:
            logger.warning("Invalid input for cultural analysis")
            return {"error": "Input too long or invalid", "safe": False}

        clean_text = sanitize_prompt(text)
        lang = lang_code or await detect_language(clean_text)

        rules = self._secure_load_rules(lang)
        if not rules:
            return {"language": lang, "safe": True, "flags": []}

        flags = []
        emotion = await detect_emotion(clean_text)

        if emotion in rules.get("sensitive_emotions", []):
            flags.append(f"Tone '{emotion}' may be considered harsh in {lang}")

        banned_phrases = rules.get("banned_phrases", [])
        for phrase in banned_phrases:
            if hmac.compare_digest(phrase.lower().encode(), clean_text.lower().encode()):
                flags.append(f"Phrase '{phrase}' is discouraged in {lang}")

        if rules.get("formal_required") and "formal" not in emotion:
             flags.append(f"Formality level insufficient for {lang}")
        
        log_event("Cultural analysis complete", metadata={"lang": lang, "flags": flags})

        return {
            "language": lang,
            "flags": flags,
            "emotion": emotion,
            "safe": len(flags) == 0,
            "security": {
                "rule_version": rules.get("_version", "unknown"),
            }
        }

    async def rephrase_to_polite(self, text: TextInput, lang_code: Optional[LanguageCode] = None) -> TextInput:
        """
        Rephrase text using cultural norms for politeness.
        """
        if not isinstance(text, str):
            return ""

        lang = lang_code or await detect_language(text)
        rules = self._secure_load_rules(lang)
        polite_prefix = rules.get("polite_prefix", "")
        polite_suffix = rules.get("polite_suffix", "")
        return f"{polite_prefix} {text} {polite_suffix}".strip()

    def get_etiquette_tip(self, lang_code: Optional[LanguageCode] = None) -> str:
        """
        Get a brief etiquette tip for a language or region.
        """
        lang = lang_code or "en"
        rules = self._secure_load_rules(lang)
        return rules.get("etiquette_tip", "No cultural tip available.")

    async def flag_inappropriate(self, text: TextInput) -> List[CulturalFlag]:
        """
        Detect and flag culturally inappropriate phrases.
        """
        if not isinstance(text, str):
            return []
        
        lang = await detect_language(text)
        rules = self._secure_load_rules(lang)
        flagged = []
        for phrase in rules.get("banned_phrases", []):
            if hmac.compare_digest(phrase.lower().encode(), text.lower().encode()):
                flagged.append(phrase)
        return flagged

    async def generate_cultural_context(self, text: TextInput, lang_code: Optional[LanguageCode] = None) -> CulturalAnalysis:
        """
        Full cultural context generation pipeline.
        """
        if not isinstance(text, str):
            return {"error": "Invalid input", "safe": False}

        lang = lang_code or await detect_language(text)
        adjusted = await self.rephrase_to_polite(text, lang)
        analysis = await self.analyze_cultural_sensitivity(text, lang)

        result = {
            "original": text,
            "adjusted": adjusted,
            "etiquette_tip": self.get_etiquette_tip(lang),
            "analysis": analysis,
            "security": {
                "audit_id": hashlib.sha256(text.encode()).hexdigest()[:16],
                "timestamp": datetime.utcnow().isoformat()
            }
        }

        log_event("CulturalContextGenerated", metadata={"result": result})
        return result

# Singleton instance
cultural_service = CulturalService()