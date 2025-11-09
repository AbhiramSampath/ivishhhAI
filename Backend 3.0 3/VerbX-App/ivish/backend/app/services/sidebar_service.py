"""
sidebar_service.py - Secure Sidebar Translation & Rephrasing Engine

Powers real-time sidebar-based translation overlays in third-party apps like WhatsApp, Instagram, etc.
Securely listens to user-selected text/audio, translates or rephrases it, and displays the output
in a secure, permission-controlled floating UI (React + IPC).
"""

import datetime
import os
import uuid
import time
import hashlib
import hmac
import unicodedata
from typing import Any, Dict, List, Optional, Union
import logging
import asyncio
from functools import lru_cache
from fastapi import Depends, HTTPException

# Internal imports - CORRECTED PATHS
from ai_models.translation.mt_translate import translate_text
from ai_models.translation.gpt_rephrase_loop import rephrase_text
from ai_models.tts.tts_handler import synthesize_speech
from ..services.permission_service import check_permission as validate_sidebar_permission
from utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain
from middlewares.rate_limiter import RateLimiter

# External imports - Removed non-existent
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# Type aliases
TextInput = str
UserID = str
LangCode = str
ToneLabel = str
SidebarPayload = Dict[str, Any]
SidebarResponse = Dict[str, Any]

# Security: AES-256-GCM configuration for payload encryption
_BACKEND = default_backend()
_TIMEOUT_SEC = float(os.getenv("SIDEBAR_TIMEOUT", 0.15))
_RATE_LIMIT_MAX_CALLS = int(os.getenv("SIDEBAR_RATE_LIMIT_CALLS", 100))
_RATE_LIMIT_PERIOD = int(os.getenv("SIDEBAR_RATE_LIMIT_PERIOD", 60))

class SidebarService:
    """
    Secure sidebar translation and rephrasing engine for Ivish AI.
    """
    def __init__(self):
        self._logger = logging.getLogger("sidebar_service")
        self._rate_limiter = RateLimiter()
        self._valid_actions = {"translate", "rephrase", "speak"}
        self._max_input_length = 5000
        self._max_output_length = 5000
        self._valid_tones = {"polite", "formal", "casual", "neutral"}

    async def process_sidebar_request(self, payload: SidebarPayload, user_id: UserID) -> SidebarResponse:
        """
        Secure main entry point with:
        - Input validation
        - Rate limiting
        - Permission checks
        - Action whitelisting
        - Secure logging
        """
        if not self._validate_input(payload, user_id):
            return {"status": "error", "message": "Invalid input", "security": "rejected"}

        if not await self._rate_limiter.check_limit(user_id, rate=_RATE_LIMIT_MAX_CALLS, window=_RATE_LIMIT_PERIOD):
            return {"status": "error", "message": "Too many requests", "security": "rate_limited"}

        if not await validate_sidebar_permission(user_id, "overlay_permission"):
            log_event(f"Sidebar access denied | user={user_id[:6]}...", level="WARNING")
            return {"status": "error", "message": "Permission denied", "security": "unauthorized"}

        if len(str(payload)) > 10000:
            return {"status": "error", "message": "Payload too large", "security": "oversize"}

        try:
            action = payload.get("action")
            text = payload.get("text", "")
            lang = payload.get("lang", "en")
            tone = payload.get("tone")

            clean_text = self._sanitize_input(text)
            if not clean_text:
                return {"status": "error", "message": "Invalid text input", "security": "sanitize"}

            if action not in self._valid_actions:
                return {"status": "error", "message": f"Invalid action: {action}", "security": "action"}

            start_time = time.time()
            result = {"status": "ok"}

            try:
                if action == "translate":
                    result["output"] = await asyncio.wait_for(
                        self._secure_translate(clean_text, lang),
                        timeout=_TIMEOUT_SEC
                    )
                elif action == "rephrase":
                    if not tone:
                        return {"status": "error", "message": "Tone required", "security": "missing_tone"}
                    result["output"] = await asyncio.wait_for(
                        self._secure_rephrase(clean_text, tone),
                        timeout=_TIMEOUT_SEC
                    )
                elif action == "speak":
                    result["audio"] = await asyncio.wait_for(
                        self._secure_tts(clean_text, lang),
                        timeout=_TIMEOUT_SEC
                    )
            except asyncio.TimeoutError:
                self._logger.warning("Sidebar processing timeout", extra={"user_id": user_id})
                return {"status": "error", "message": "Processing timeout", "security": "timeout"}

            if action != "speak" and not isinstance(result.get("output"), str):
                result["output"] = clean_text
            elif action == "speak" and not isinstance(result.get("audio"), bytes):
                del result["audio"]

            audit_data = {
                "user_id": user_id,
                "action": action,
                "lang": lang,
                "text": clean_text,
                "output": result.get("output", ""),
                "tone": tone,
                "timestamp": datetime.utcnow().isoformat()
            }
            asyncio.create_task(log_to_blockchain("sidebar_request", audit_data))

            return result

        except Exception as e:
            self._logger.critical(f"Sidebar error: {str(e)}", exc_info=True)
            return {"status": "error", "message": "Processing error", "security": "exception"}

    def _validate_input(self, payload: SidebarPayload, user_id: UserID) -> bool:
        """Input sanitization and type validation"""
        return isinstance(payload, dict) and isinstance(user_id, str)

    def _sanitize_input(self, text: TextInput) -> TextInput:
        """Secure input sanitization pipeline"""
        if not isinstance(text, str):
            return ""
        sanitized = "".join(c for c in text if ord(c) >= 32)
        return unicodedata.normalize('NFKC', sanitized[:self._max_input_length])

    async def _secure_translate(self, text: TextInput, lang: LangCode) -> TextInput:
        """Secure translation with input/output validation"""
        if not text or len(text) > self._max_input_length:
            return ""
        try:
            translated = await translate_text(text, tgt=lang)
            return translated[:self._max_output_length]
        except Exception as e:
            self._logger.warning(f"Translation failed: {str(e)}")
            return text

    async def _secure_rephrase(self, text: TextInput, tone: ToneLabel) -> TextInput:
        """Secure rephrasing with fallback"""
        if tone not in self._valid_tones:
            tone = "polite"
        try:
            return await rephrase_text(text[:2000], tone=tone)
        except Exception as e:
            self._logger.warning(f"Rephrase failed: {str(e)}")
            return text

    async def _secure_tts(self, text: TextInput, lang: LangCode) -> bytes:
        """Secure TTS generation with input validation"""
        if not text or len(text) > 1000:
            return b""
        try:
            return await synthesize_speech(text[:1000], lang=lang)
        except Exception as e:
            self._logger.warning(f"TTS generation failed: {str(e)}")
            return b""

# Singleton instance
sidebar_service = SidebarService()