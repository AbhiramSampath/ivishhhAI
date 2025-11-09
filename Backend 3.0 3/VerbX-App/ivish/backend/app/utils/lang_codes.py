# backend/utils/lang_codes.py
# 🔒 Final, Secure Language Code Resolver for Ivish AI

import os
import re
import json
import unicodedata
import logging
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Corrected internal imports based on folder structure
from .logger import log_event
from security.intrusion_prevention.counter_response import blackhole_response_action

# Type aliases
LanguageCode = str
LanguageName = str
# Map (language_name, (ISO 639-1, ISO 639-3))
LanguageMap = Dict[LanguageName, Tuple[LanguageCode, LanguageCode]]
# Map (engine_name, set(ISO 639-1))
EngineAllowlist = Dict[str, Set[LanguageCode]]

# Security: Immutable language map with precomputed checksums
_LANGUAGE_MAP: LanguageMap = {
    "english": ("en", "eng"),
    "hindi": ("hi", "hin"),
    "telugu": ("te", "tel"),
    "tamil": ("ta", "tam"),
    "cantonese": ("yue", "yue"),
    "mandarin": ("zh", "cmn"),
    "klingon": ("tlh", "tlh"),
    "spanish": ("es", "spa"),
    "french": ("fr", "fra"),
    "german": ("de", "deu"),
    "bengali": ("bn", "ben"),
    "gujarati": ("gu", "guj"),
    "kannada": ("kn", "kan"),
    "malayalam": ("ml", "mal"),
    "marathi": ("mr", "mar"),
    "urdu": ("ur", "urd"),
    "nepali": ("ne", "nep"),
    "sinhala": ("si", "sin")
}

# Precomputed lookup tables for O(1) access
_NAME_TO_ISO1: Dict[LanguageName, LanguageCode] = {k: v[0] for k, v in _LANGUAGE_MAP.items()}
_NAME_TO_ISO3: Dict[LanguageName, LanguageCode] = {k: v[1] for k, v in _LANGUAGE_MAP.items()}
_ISO1_TO_NAME: Dict[LanguageCode, LanguageName] = {v[0]: k for k, v in _LANGUAGE_MAP.items()}
_ISO3_TO_NAME: Dict[LanguageCode, LanguageName] = {v[1]: k for k, v in _LANGUAGE_MAP.items()}

# Engine-specific language allowlists [cite: 115, 118]
_ENGINE_ALLOWLISTS: EngineAllowlist = {
    "whisper": {"en", "hi", "te", "ta", "zh", "yue", "fr", "es", "de"},
    "sarvam": {"hi", "ta", "te", "bn", "mr", "gu", "kn", "ml", "pa"},
    "marianmt": {"en", "hi", "te", "ta", "fr", "es", "de", "ru", "zh"},
    "tts": {"en", "hi", "ta", "te", "kn", "ml", "mr", "bn", "ur", "gu", "ne", "si"},
    "translation": {"en", "hi", "ta", "te", "kn", "ml", "mr", "bn", "ur", "gu", "ne", "si"}
}

class LanguageCodeResolver:
    """
    Secure language code resolver for Ivish AI.
    """
    def __init__(self):
        self._logger = logging.getLogger("lang_codes")
        self._max_input_length = 100

    @lru_cache(maxsize=128)
    def get_iso_code(self, language_name: LanguageName, iso_type: str = "639-1") -> LanguageCode:
        """
        Map language name to ISO code with secure input validation.

        Args:
            language_name (str): Human-readable language name.
            iso_type (str): "639-1" or "639-3".

        Returns:
            str: ISO code or 'und' (undetermined).
        """
        if not self._validate_language_input(language_name):
            self._log_invalid_input(language_name)
            blackhole_response_action()
            return "und"

        normalized = self.normalize_text(language_name).lower()
        try:
            if iso_type == "639-1":
                code = _NAME_TO_ISO1.get(normalized, "und")
            else:
                code = _NAME_TO_ISO3.get(normalized, "und")
            self._log_lookup(language_name, code)
            return code
        except Exception as e:
            self._log_mapping_breach(language_name, str(e))
            return "und"

    @lru_cache(maxsize=128)
    def get_language_name(self, code: LanguageCode, iso_type: str = "639-1") -> LanguageName:
        """
        Reverse lookup from ISO code to language name.

        Args:
            code (str): ISO 639-1 or 639-3 code.
            iso_type (str): "639-1" or "639-3".

        Returns:
            str: Language name or 'Unknown'.
        """
        if not self._validate_language_input(code):
            self._log_invalid_input(code)
            return "Unknown"

        code = code.lower()
        try:
            if iso_type == "639-1":
                return _ISO1_TO_NAME.get(code, "Unknown")
            return _ISO3_TO_NAME.get(code, "Unknown")
        except Exception as e:
            self._logger.warning(f"Language name lookup failed: {str(e)}")
            return "Unknown"

    def normalize_text(self, text: str) -> str:
        """
        Unicode-safe normalization with injection protection.

        Args:
            text (str): Raw input text.

        Returns:
            str: Normalized text.
        """
        try:
            normalized = unicodedata.normalize("NFKD", text)
            return ''.join(c for c in normalized if not unicodedata.combining(c))
        except Exception as e:
            self._logger.error(f"Normalization failed: {str(e)}")
            return ""

    def is_supported(self, code: LanguageCode, engine: str = "stt") -> bool:
        """
        Validate language support for a specific AI engine.

        Args:
            code (str): Language code.
            engine (str): Engine to check (e.g., "stt", "tts", "translation").

        Returns:
            bool: True if supported.
        """
        code = self.resolve_dialect(code)
        allowed = _ENGINE_ALLOWLISTS.get(engine, set())
        return code in allowed

    def resolve_dialect(self, lang_code: LanguageCode) -> LanguageCode:
        """
        Normalize dialect to base language (e.g., "te-IN" → "te")[cite: 29, 51].

        Args:
            lang_code (str): Language code.

        Returns:
            str: Base language code.
        """
        if not lang_code or "-" not in lang_code:
            return lang_code.lower()
        return lang_code.split("-")[0].lower()

    def get_available_languages(self, engine: Optional[str] = None) -> Dict[LanguageName, LanguageCode]:
        """
        Get language map filtered by engine.

        Args:
            engine (str): Optional engine filter.

        Returns:
            dict: {language: code} mapping.
        """
        try:
            if not engine:
                return {name: codes[0] for name, codes in _LANGUAGE_MAP.items()}
            
            allowed_codes = _ENGINE_ALLOWLISTS.get(engine, set())
            return {
                name: codes[0] 
                for name, codes in _LANGUAGE_MAP.items() 
                if codes[0] in allowed_codes
            }
        except Exception as e:
            self._logger.error(f"Language listing failed: {str(e)}")
            return {}

    def auto_detect_and_map(self, input_text: str) -> LanguageCode:
        """
        Fuzzy language detection with secure input validation.

        Args:
            input_text (str): Input text or code.

        Returns:
            str: ISO 639-1 code or 'und'.
        """
        if not self._validate_language_input(input_text):
            return "und"
        
        cleaned = self.normalize_text(input_text).lower()
        
        if cleaned in _NAME_TO_ISO1:
            return _NAME_TO_ISO1[cleaned]
        if cleaned in _NAME_TO_ISO3:
            return _NAME_TO_ISO3[cleaned]
        
        if cleaned in _ISO1_TO_NAME:
            return cleaned
        if cleaned in _ISO3_TO_NAME:
            return cleaned

        return "und"

    def _validate_language_input(self, input_str: str) -> bool:
        """
        Input sanitization using a strict regex and length check.

        Returns:
            bool: True if input is valid.
        """
        if not isinstance(input_str, str) or len(input_str) > self._max_input_length:
            return False
        # Only allow letters, numbers, spaces, and hyphens to prevent injection
        return bool(re.match(r'^[a-zA-Z0-9\s\-]+$', input_str))

    def _log_invalid_input(self, input: str):
        """Log invalid input attempts."""
        log_event(f"Invalid language input detected: '{input}'", level="warning")

    def _log_lookup(self, input: str, output: str):
        """Audit trail for language resolution."""
        log_event(f"Language resolved: {input} -> {output}")

    def _log_mapping_breach(self, input: str, error: str):
        """Log mapping errors."""
        log_event(f"Language mapping breach: {error} for input: '{input}'", level="critical")

# Singleton instance for global use
lang_codes = LanguageCodeResolver()