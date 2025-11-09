# integrations/zoom/zoom_transcript.py
# 🔒 Nuclear-Grade Zoom Meeting Transcript Enhancer
# SECURITY HARDENING BY IVISH ARCHITECTURE TEAM

import os
import uuid
import json
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import hmac
import logging
from functools import lru_cache
from fastapi import APIRouter, Request, HTTPException, Header
from pydantic import BaseModel, validator, Field

# Internal imports (corrected based on project structure)
from ai_models.translation.dialect_adapter import detect_language
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.mt_translate import translate_text
from ai_models.translation.gpt_rephrase_loop import summarize_text
from backend.app.utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain
from config.settings import STORE_TRANSCRIPTS
from security.zoom_validator import verify_zoom_signature


from backend.app.db.mongo import secure_insert_document

# Type aliases
TranscriptData = Dict[str, Any]
ZoomPayload = Dict[str, Any]

# Security: Centralized HMAC key from environment variables
_ZOOM_HMAC_KEY = os.getenv("ZOOM_HMAC_KEY")
if not _ZOOM_HMAC_KEY:
    raise RuntimeError("ZOOM_HMAC_KEY environment variable must be set for secure signature verification.")

router = APIRouter()
zoom_transcript_logger = logging.getLogger("zoom_transcript")
MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB max
MAX_TRANSCRIPT_LENGTH = int(os.getenv("ZOOM_MAX_TRANSCRIPT_LENGTH", "100000"))  # Prevent DoS

class TranscriptPayload(BaseModel):
    """
    Strict validation schema for Zoom transcript payload
    """
    transcript: str
    meeting_id: str
    user_id: str
    event_id: Optional[str] = Field(None, alias="X-Zoom-Webhook-Event-ID")
    event_ts: Optional[int] = Field(None, alias="X-Zoom-Webhook-Event-TS")
    room_id: Optional[str] = None
    timestamp: Optional[int] = None

class ZoomTranscriptProcessor:
    """
    Secure Zoom transcript handler for Ivish AI.
    """

    def __init__(self):
        self._logger = logging.getLogger("zoom_transcript")
        self._max_transcript_length = MAX_TRANSCRIPT_LENGTH
        self._supported_languages = ["en", "hi", "ta", "te", "kn", "bn", "gu", "ml", "mr", "ur", "ne", "si"]

    @router.post("/zoom/transcript")
    async def handle_zoom_transcript(
        self,
        request: Request,
        x_zoom_signature: Optional[str] = Header(None)
    ) -> Dict:
        """
        Main Zoom webhook handler with:
        - HMAC signature verification
        - Input validation
        - AI processing pipeline
        """
        try:
            raw_body = await request.body()
            if len(raw_body) > MAX_PAYLOAD_SIZE:
                self._log_request_too_large()
                raise HTTPException(status_code=413, detail="Payload too large")

            if not verify_zoom_signature(raw_body.decode("utf-8"), x_zoom_signature, _ZOOM_HMAC_KEY):
                self._log_invalid_signature()
                raise HTTPException(status_code=403, detail="Invalid signature")

            try:
                payload_data = json.loads(raw_body)
                payload = TranscriptPayload(**payload_data)
            except json.JSONDecodeError:
                self._log_invalid_payload(None)
                raise HTTPException(status_code=400, detail="Invalid JSON payload")
            except Exception as e:
                self._log_invalid_payload(e)
                raise HTTPException(status_code=400, detail=f"Invalid payload: {str(e)}")

            sanitized_text = self._sanitize_transcript(payload.transcript)
            if not sanitized_text:
                self._log_empty_transcript()
                raise HTTPException(status_code=400, detail="Empty transcript")

            lang = self._detect_language(sanitized_text)
            processed = self._enhance_transcript_safely(sanitized_text, lang)

            meeting_id = payload.meeting_id
            user_id = payload.user_id
            timestamp = datetime.utcnow().isoformat() + "Z"

            data = {
                "meeting_id": meeting_id,
                "user_id": user_id,
                "original_lang": lang,
                "timestamp": timestamp,
                **processed,
                "security": {
                    "verified": True,
                    "event_id": payload.event_id,
                    "source": "zoom_webhook",
                    "signature_verified": True
                }
            }

            if STORE_TRANSCRIPTS:
                self._store_transcript_securely(data)

            self._log_to_blockchain(sanitized_text, data)
            self._audit_agent.update(data)

            self._log_processed_event(meeting_id)
            return {
                "status": "success",
                "summary": processed.get("summary"),
                "security": "validated"
            }

        except HTTPException:
            raise
        except Exception as e:
            self._log_processing_error(str(e))
            raise HTTPException(status_code=500, detail="Internal processing error")

    def _sanitize_transcript(self, text: str) -> str:
        """Prevent Unicode exploits and limit length."""
        sanitized = ''.join(
            char for char in text
            if (ord(char) in range(32, 0xD7FF) or
                ord(char) in range(0xE000, 0xFFFF))
        )
        return sanitized[:self._max_transcript_length]

    def _detect_language(self, text: str) -> str:
        """Detect transcript language with fallback."""
        lang = detect_language(text)
        if lang not in self._supported_languages:
            return "en"
        return lang

    def _enhance_transcript_safely(self, text: str, lang_hint: str) -> Dict:
        """Wrapped AI processing with fallbacks."""
        try:
            translated = self._translate_if_needed(text, lang_hint)
            tone = self._detect_emotion(translated)
            summary = self._generate_summary(translated)

            return {
                "original_text": text,
                "translated_text": translated,
                "tone": tone,
                "summary": summary,
                "processing_metadata": {
                    "translation_success": translated != text,
                    "truncated": len(text) > MAX_TRANSCRIPT_LENGTH,
                    "lang_detected": lang_hint,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
        except Exception as e:
            self._logger.error(f"Transcript enhancement failed: {str(e)}")
            return {
                "translated_text": text,
                "tone": {"error": "processing_failed"},
                "summary": "Summary unavailable",
                "processing_metadata": {
                    "error": str(e)
                }
            }

    def _translate_if_needed(self, text: str, source_lang: str) -> str:
        """Translate to English if source is non-English."""
        if source_lang == "en":
            return text
        return translate_text(text, target_lang="en", source_lang=source_lang, fallback=text)

    def _detect_emotion(self, text: str) -> Dict:
        """Detect emotional tone in transcript."""
        try:
            return detect_emotion(text[:10_000])
        except Exception as e:
            self._logger.error(f"Emotion detection failed: {str(e)}")
            return {"error": "emotion_detection_failed"}

    def _generate_summary(self, text: str) -> str:
        """Generate summary with input validation."""
        try:
            return summarize_text(text[:10_000])
        except Exception as e:
            self._logger.error(f"Summary generation failed: {str(e)}")
            return "Summary unavailable"

    def _store_transcript_securely(self, data: Dict):
        """Secure encrypted storage with access controls."""
        try:
            secure_data = {
                **data,
                "security": {
                    **data.get("security", {}),
                    "encrypted": True
                }
            }
            secure_insert_document("zoom_transcripts", secure_data, ttl_days=30)
        except Exception as e:
            self._logger.error(f"Transcript storage failed: {str(e)}")

    def _log_to_blockchain(self, text: str, data: Dict):
        """Immutable audit log."""
        try:
            fingerprint = self._generate_transcript_fingerprint(text)
            log_to_blockchain("zoom_transcript", {
                "meeting_id": data.get("meeting_id"),
                "user_id": data.get("user_id"),
                "transcript_fingerprint": fingerprint,
                "summary_hash": hashlib.sha256(data.get("summary", "").encode()).hexdigest(),
                "timestamp": data.get("timestamp"),
                "security_status": "validated"
            })
        except Exception as e:
            self._logger.error(f"Blockchain logging failed: {str(e)}")

    def _generate_transcript_fingerprint(self, text: str) -> str:
        """Create SHA-256 hash for audit."""
        return hashlib.sha256(text.encode()).hexdigest()

    # === SECURITY LOGGING ===
    def _log_request_too_large(self):
        self._logger.warning("Zoom transcript request too large", extra={"security_level": "high"})

    def _log_invalid_signature(self):
        self._logger.critical("Zoom transcript signature invalid", extra={"security_level": "critical"})

    def _log_invalid_payload(self, error: Optional[Exception]):
        self._logger.warning(f"Invalid Zoom payload: {str(error)}", extra={"security_level": "high"})

    def _log_empty_transcript(self):
        self._logger.warning("Zoom transcript is empty", extra={"security_level": "medium"})

    def _log_processed_event(self, meeting_id: str):
        self._logger.info(f"Zoom transcript processed | meeting={meeting_id}", extra={"security_level": "medium"})

    def _log_processing_error(self, error: str):
        self._logger.error(f"Zoom transcript enhancement failed: {error}", extra={"security_level": "high"})

    def _log_security_breach(self, reason: str):
        self._logger.critical(f"Zoom security breach: {reason}", extra={"security_level": "critical"})

# Singleton instance
zoom_transcript_processor = ZoomTranscriptProcessor()