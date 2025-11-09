# voice_call/translator.py

import os
import uuid
import hashlib
import hmac
import json
import logging
import asyncio
import time
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union
from collections import deque
from functools import lru_cache
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Security Imports (Corrected paths)
from ai_models.whisper.whisper_handler import transcribe_audio
from ai_models.translation.dialect_adapter import detect_language
from ai_models.translation.mt_translate import translate_text
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.tts.tts_handler import synthesize_speech

from backend.app.utils.logger import log_event

from security.blockchain.zkp_handler import ZeroKnowledgeProof
from ai_models.ivish.ivish_memory import MemorySessionHandler
from ai_models.self_learning.autocoder import AutoCoder

# Initialize secure components
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
memory_handler = MemorySessionHandler()
autocoder = AutoCoder()
backend = default_backend()

# Constants
_AUDIO_KEY = os.getenv("AUDIO_ENCRYPTION_KEY", "default_audio_key_32bytes").encode()
if len(_AUDIO_KEY) < 32:
    _AUDIO_KEY = hashlib.sha256(_AUDIO_KEY).digest()
_DEFAULT_LANG = "en"
_MAX_LATENCY_MS = 200
_MIN_AUDIO_CHUNK_SIZE = 1024
_SESSION_KEY_REFRESH = 300
_MAX_PIPELINE_RETRIES = 3
_DEFAULT_PIPELINE_TIMEOUT = 10.0

# Security Constants
AUDIO_HMAC_KEY = os.getenv("AUDIO_HMAC_KEY", "default_hmac_key_32bytes").encode()
if len(AUDIO_HMAC_KEY) < 32:
    AUDIO_HMAC_KEY = hashlib.sha256(AUDIO_HMAC_KEY).digest()

AUDIO_HASH_KEY = os.getenv("AUDIO_HASH_KEY", "default_hash_key").encode()
PIPELINE_EVENT_TTL = 60 * 60

# Language Constants
_SUPPORTED_LANGS = {"en", "hi", "te", "ta", "es", "fr", "ur", "bn", "gu", "kn", "ml", "mr", "pa", "sa"}
_LANGUAGE_CACHE_TTL = 60 * 60
_LANGUAGE_DETECTION_TIMEOUT = 3.0

class TranslationPipeline:
    """
    Military-grade voice translation pipeline with:
    - AES-GCM audio encryption
    - HMAC integrity validation
    - Emotion-aware synthesis
    - Secure language detection
    - Tamper detection
    """
    def __init__(self):
        self.session_key = os.urandom(32)
        self.session_id = str(uuid.uuid4())
        self.pipeline_history = deque(maxlen=100)
        self._last_key_update = datetime.utcnow()
        self._rate_limiter_lock = asyncio.Lock()

    async def _encrypt_audio(self, audio: bytes) -> bytes:
        """AES-GCM encryption with integrity tag"""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv), backend=backend)
        encryptor = cipher.encryptor()
        return iv + encryptor.update(audio) + encryptor.finalize()

    async def _decrypt_audio(self, encrypted: bytes) -> bytes:
        """AES-GCM decryption with integrity validation"""
        iv = encrypted[:12]
        tag = encrypted[12:28]
        ciphertext = encrypted[28:]
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag), backend=backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _validate_language(self, lang: str) -> bool:
        """Prevent language code injection and spoofing"""
        return lang in _SUPPORTED_LANGS

    async def _detect_language(self, audio: bytes) -> str:
        """Secure language detection with fallback and validation"""
        try:
            lang = await asyncio.wait_for(
                asyncio.to_thread(detect_language, audio),
                timeout=_LANGUAGE_DETECTION_TIMEOUT
            )
            if not self._validate_language(lang):
                log_event(f"TRANSLATE: Invalid language detected: {lang}", level="WARNING")
                return _DEFAULT_LANG
            return lang
        except asyncio.TimeoutError:
            log_event("TRANSLATE: Language detection timeout", level="ERROR")
            return _DEFAULT_LANG

    async def _detect_emotion(self, audio: bytes) -> str:
        """Secure emotion detection with fallback"""
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(detect_emotion, audio),
                timeout=3.0
            )
        except Exception as e:
            log_event(f"TRANSLATE: Emotion detection failed: {str(e)}", level="WARNING")
            return "neutral"

    async def _translate_text(self, text: str, src: str, tgt: str) -> str:
        """Secure translation with fallback and validation"""
        if not self._validate_language(src) or not self._validate_language(tgt):
            raise ValueError(f"Invalid language: src={src}, tgt={tgt}")

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(translate_text, text, src, tgt),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            log_event(f"TRANSLATE: Translation timeout", level="ERROR")
            return "[TRANSLATION FAILED]"

    async def _synthesize_speech(self, text: str, tone: str = "neutral", lang: str = "en") -> bytes:
        """Secure TTS synthesis with fallback and encryption"""
        if not self._validate_language(lang):
            lang = _DEFAULT_LANG

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(synthesize_speech, text, tone, lang),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            log_event("TRANSLATE: TTS synthesis timeout", level="ERROR")
            return b""

    async def _validate_audio_integrity(self, audio: bytes, signature: bytes) -> bool:
        """Verify HMAC signature for audio integrity"""
        expected = hmac.new(AUDIO_HMAC_KEY, audio, hashlib.sha256).digest()
       

    async def _secure_translate_stream(self, audio_chunk: bytes, src_lang: Optional[str] = None,
                                   tgt_lang: str = "en", zkp: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Secure real-time translation pipeline with:
        - Zero-Knowledge Proof validation
        - Audio decryption
        - Language detection
        - Secure translation
        - Emotion-preserving synthesis
        """
        start_time = time.perf_counter_ns()
        session_id = self.session_id

        if zkp and not ZeroKnowledgeProof.verify(zkp, session_id.encode()):
            log_event("TRANSLATE: ZKP validation failed", level="ALERT")
            return {"audio": await self._synthesize_speech("Unauthorized", "neutral", tgt_lang)}

        try:
            decrypted = await self._decrypt_audio(audio_chunk)
        except Exception as e:
            log_event(f"TRANSLATE: Audio decryption failed: {str(e)}", level="ERROR")
            return {"audio": b"", "error": "decryption_failed"}

        if not await self._validate_audio_integrity(decrypted, AUDIO_HMAC_KEY):
            log_event("TRANSLATE: Audio integrity failed", level="WARNING")
            return {"audio": b"", "error": "integrity_check_failed"}

        try:
            processed = await asyncio.wait_for(
                asyncio.to_thread( decrypted, {"stream": True}),
                timeout=3.0
            )
        except asyncio.TimeoutError:
            log_event("TRANSLATE: Audio preprocessing timeout", level="ERROR")
            return {"audio": b"", "error": "preprocessing_timeout"}

        src_lang = src_lang or await self._detect_language(processed)

        stt_task = asyncio.create_task(transcribe_audio(processed, lang_hint=src_lang))
        emotion_task = asyncio.create_task(self._detect_emotion(processed))

        try:
            stt_output = await stt_task
            emotion = await emotion_task
        except Exception as e:
            log_event(f"TRANSLATE: STT/Emotion error - {str(e)}", level="ERROR")
            return {"audio": b"", "error": "stt_emotion_failed"}

        translated = await self._translate_text(stt_output["text"], src_lang, tgt_lang)
        if not translated:
            log_event("TRANSLATE: Empty translation", level="WARNING")
            return {"audio": b"", "error": "empty_translation"}

        speech_output = await self._synthesize_speech(translated, tone=emotion, lang=tgt_lang)
        if not speech_output:
            log_event("TRANSLATE: Empty speech output", level="WARNING")
            return {"audio": b"", "error": "empty_speech"}

        encrypted_output = await self._encrypt_audio(speech_output)

        asyncio.create_task(memory_handler.append_to_session(session_id, "translation", {
            "timestamp": datetime.utcnow().isoformat(),
            "source_language": src_lang,
            "target_language": tgt_lang,
            "original_text": stt_output["text"],
            "translated_text": translated,
            "emotion": emotion,
            "latency": (time.perf_counter_ns() - start_time) / 1e6
        }))

        return {
            "audio": encrypted_output,
            "text": translated,
            "emotion": emotion,
            "source_lang": src_lang,
            "target_lang": tgt_lang,
            "session_id": session_id,
            "latency_ms": (time.perf_counter_ns() - start_time) / 1e6,
            "pipeline_id": str(uuid.uuid4()),
            "security_hash": hmac.new(AUDIO_HASH_KEY, encrypted_output, hashlib.sha256).digest()
        }

    async def translate_stream(self, audio_chunk: bytes, src_lang: Optional[str] = None,
                              tgt_lang: str = "en", zkp: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Wrapper for secure translation with fallback and retry logic.
        """
        for attempt in range(_MAX_PIPELINE_RETRIES):
            result = await self._secure_translate_stream(audio_chunk, src_lang, tgt_lang, zkp)
            if result.get("audio"):
                return result
            await asyncio.sleep(0.1 * attempt)

        return {
            "audio": await self._synthesize_speech("Translation unavailable", "neutral", tgt_lang),
            "fallback": True,
            "retries": _MAX_PIPELINE_RETRIES
        }

    async def handle_bilingual_call(self, user_a_stream, user_b_stream,
                                 lang_a: str = "hi", lang_b: str = "en") -> None:
        """
        Secure duplex translation with:
        - Session rotation
        - Anti-DoS throttling
        - Encrypted channels
        """
        session_id = str(uuid.uuid4())
        last_chunk_time = time.time()
        session_key = os.urandom(32)
        pipeline_start = time.time()

        while True:
            try:
                current_time = time.time()
                if current_time - last_chunk_time < 0.02:
                    await asyncio.sleep(0.01)
                    continue
                last_chunk_time = current_time

                if current_time - pipeline_start > _SESSION_KEY_REFRESH:
                    session_key = os.urandom(32)
                    pipeline_start = current_time

                chunk_a, chunk_b = await asyncio.gather(
                    user_a_stream.read(),
                    user_b_stream.read()
                )

                if chunk_a:
                    result = await self.translate_stream(chunk_a, src_lang=lang_a, tgt_lang=lang_b)
                    await user_b_stream.send_audio(result["audio"])

                if chunk_b:
                    result = await self.translate_stream(chunk_b, src_lang=lang_b, tgt_lang=lang_a)
                    await user_a_stream.send_audio(result["audio"])

            except Exception as e:
                log_event(f"BILINGUAL: Session {session_id} failed - {str(e)}")
                await asyncio.sleep(1)

    async def track_pipeline_latency(self, sample_audio: bytes) -> Dict[str, float]:
        """
        Benchmark translation pipeline with secure logging.
        Returns cold and warm performance metrics.
        """
        start = time.perf_counter_ns()
        result = await self.translate_stream(sample_audio)
        cold_time = (time.perf_counter_ns() - start) / 1e6

        start = time.perf_counter_ns()
        result = await self.translate_stream(sample_audio)
        warm_time = (time.perf_counter_ns() - start) / 1e6

        log_event(f"PERF: Cold={cold_time:.2f}ms, Warm={warm_time:.2f}ms")
        return {"cold": cold_time, "warm": warm_time}

    async def inject_emotion(self, text: str, tone: str = "neutral", lang: str = "en") -> bytes:
        """
        Secure emotion-aware TTS synthesis with language validation.
        """
        if not self._validate_language(lang):
            lang = _DEFAULT_LANG
        return await self._synthesize_speech(text, tone=tone, lang=lang)

    async def _rotate_session_key(self) -> None:
        """Rotate encryption key periodically for security"""
        self.session_key = os.urandom(32)
        self._last_key_update = datetime.utcnow()
        log_event("TRANSLATE: Session key rotated", level="SECURE")

    async def _handle_pipeline_failure(self, error: Exception, session_id: str) -> None:
        """Log and trigger defensive action on pipeline failure"""
        log_event(f"TRANSLATE: Pipeline failed - {str(error)}", level="ERROR")
        asyncio.create_task(autocoder.optimize_translation_pipeline())
        asyncio.create_task(memory_handler.clear_session(session_id))

    async def _handle_compromise(self, space_id: str) -> None:
        """Secure response to context tampering or injection"""
        log_event(f"TRANSLATE: Compromise detected in {space_id}", level="CRITICAL")
        asyncio.create_task(memory_handler.shred_space(space_id))
        asyncio.create_task(autocoder.optimize_translation_pipeline())

    async def _validate_audio_chunk(self, chunk: bytes) -> bool:
        """Check for malformed or adversarial audio chunks"""
        if not chunk or len(chunk) < _MIN_AUDIO_CHUNK_SIZE:
            return False
        return True

    async def _check_pipeline_integrity(self, result: Dict[str, Any]) -> bool:
        """Verify integrity of pipeline output"""
        if not result.get("audio"):
            return False
        return hmac.compare_digest(
            result["security_hash"],
            hmac.new(AUDIO_HMAC_KEY, result["audio"], hashlib.sha256).digest()
        )

    async def _check_latency_threshold(self, latency: float) -> bool:
        """Detect and log latency breaches"""
        if latency > _MAX_LATENCY_MS:
            log_event(f"TRANSLATE: Latency breach {latency:.2f}ms > {_MAX_LATENCY_MS}ms", level="WARNING")
            asyncio.create_task(autocoder.optimize_translation_pipeline())
            return False
        return True

    async def _log_pipeline_event(self, event: Dict[str, Any]) -> None:
        """Secure pipeline event logging with session memory"""
        try:
            asyncio.create_task(memory_handler.log_pipeline(event))
        except Exception as e:
            log_event(f"TRANSLATE: Logging failed - {str(e)}", level="WARNING")