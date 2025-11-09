import spacy
from typing import Any, Dict, List, Optional, Union
import hashlib
import logging
import os
import json
from datetime import datetime, timezone
import hmac

# Corrected Imports based on Project Architecture

from security.encryption_utils import encrypt_data, decrypt_data
from backend.app.utils.logger import log_event
from backend.app.services.ivish_service import SessionManager
from ai_control.safety_decision_manager import AuditAgent

# External imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from Crypto.Cipher import AES  # Security: AES for sensitive entity encryption
from Crypto.Random import get_random_bytes

# Type aliases
Entity = Dict[str, Any]
NERResult = Dict[str, Union[str, List[Entity], Dict[str, Any]]]

# Security: Ephemeral encryption keys (rotated per-session)
# This key should be unique per instance, not a fixed value
_AES_KEY = get_random_bytes(16)
_NONCE = get_random_bytes(12)


class NERHandler:
    """
    Secure, multilingual NER handler for Ivish AI.

    Features:
    - Real-time entity extraction
    - Multilingual support
    - Code-mixing detection
    - Entity normalization
    - Batch inference
    - Security hardening
    """

    def __init__(self):
        self._supported_languages = self._load_supported_languages()
        self._session_key = self._generate_session_key()
        self._logger = logging.getLogger("ner_handler")
        self._session_manager = SessionManager()
        self._audit_agent = AuditAgent()
        self._models = {}  # Cache for loaded spaCy models

    def extract_entities(self, text: str, lang_code: Optional[str] = None) -> NERResult:
        """
        Extract named entities from text with language detection.

        Args:
            text (str): Input text
            lang_code (str, optional): Language code. Defaults to None.

        Returns:
            dict: NER result with entities, language, and metadata
        """

    def bulk_entity_tagging(self, texts: List[str], lang_code: Optional[str] = None) -> List[NERResult]:
        """
        Process a batch of texts for entity tagging.
        """
        MAX_BATCH_SIZE = 50
        if len(texts) > MAX_BATCH_SIZE:
            raise ValueError(f"Max batch size {MAX_BATCH_SIZE} exceeded")

        return [self.extract_entities(text, lang_code) for text in texts]

    def _sanitize_input(self, text: str) -> str:
        """Prevent model poisoning via Unicode/control characters"""
        return ''.join(char for char in text if ord(char) > 31 and ord(char) != 127)

    def _is_language_supported(self, lang_code: str) -> bool:
        """Validate language code against allowlist"""
        return lang_code in self._supported_languages

    def _fallback_language_response(self, clean_input: str) -> NERResult:
        """Graceful fallback for unsupported languages"""
        return {
            "error": "unsupported_language",
            "security": "FALLBACK_EN",
            "input": clean_input
        }

    def _encrypt_sensitive_entities(self, entities: List[Entity]) -> List[Entity]:
        """Obfuscate sensitive entities (PERSON, ORG)"""
        for ent in entities:
            if ent['label'] in ['PERSON', 'ORG']:
                try:
                    encrypted_text = encrypt_data(ent['text'].encode(), key=self._session_key)
                    ent['text'] = encrypted_text.decode('latin-1')  # Store as string
                except Exception as e:
                    self._logger.error(f"Entity encryption failed: {e}")
                    ent['text'] = "[ENCRYPTION_FAILED]"
        return entities

    def _error_response(self, error: str, security_status: str) -> NERResult:
        """Generic error to avoid leaking stack traces"""
        return {
            "error": error,
            "security": security_status
        }

    def _generate_session_key(self) -> bytes:
        """Generate session-specific encryption key"""
        return get_random_bytes(16)

    def _load_supported_languages(self) -> List[str]:
        """Immutable allowlist of supported languages"""
        return [
            "en", "hi", "ta", "te", "kn", "bn", "gu", "ml", "mr", "ur", "ne", "si"
        ]

    def _format_entities(self, doc) -> List[Entity]:
        """
        Format spaCy entities. Confidence is set to 1.0 by default, as spaCy does not provide per-entity confidence.
        """
        return [
            {
                "text": ent.text,
                "label": ent.label_,
                "start": ent.start_char,
                "end": ent.end_char,
                "confidence": 1.0
            }
            for ent in doc.ents
        ]

def get_supported_languages() -> List[str]:
    """Return list of supported languages"""
    return ner_handler._supported_languages

# Singleton instance
ner_handler = NERHandler()
if __name__ != "__main__":
    # Regenerate session key and other security-critical components
    # This block ensures that each import (e.g., in a new process) gets fresh keys
    ner_handler._session_key = get_random_bytes(16)