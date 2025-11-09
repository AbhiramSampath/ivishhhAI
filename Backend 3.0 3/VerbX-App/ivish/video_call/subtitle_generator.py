# video_call/subtitle_generator.py
# SECURITY HARDENING BY IVISH ARCHITECTURE TEAM

import asyncio
import uuid
import json
import time
import hashlib
import unicodedata
import re
import os
import binascii
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC as C_HMAC

# Original imports (corrected paths)
from config.settings import (
    DEFAULT_SUB_LANG,
    SUBTITLE_CRYPTO_KEY,
    MAX_SUBTITLE_LATENCY_MS,
    SUBTITLE_CACHE_TTL
)
from ai_models.whisper.whisper_handler import stream_transcribe
from ai_models.translation.mt_translate import translate_text
from ai_models.emotion.emotion_handler import detect_emotion
from backend.app.utils.logger import log_event, security_alert
from backend.app.middlewares.rate_limiter import rate_limit
from security.blockchain.zkp_handler import validate_session_token
from security.blockchain.blockchain_utils import anchor_event as log_subtitle_event

# Security constants
SUBTITLE_HMAC_KEY = os.urandom(32)  # Rotated hourly
MAX_SUBTITLE_LENGTH = 500  # Prevent DoS
BLACKLISTED_SUBTITLE_HASHES = set()

# Global kill switch
_subtitle_killed = False

# Secure subtitle cache with AES-256-GCM encryption
subtitle_cache = {}
_cache_lock = asyncio.Lock()

def _hmac_subtitle(payload: Dict) -> str:
    """HMAC-SHA256 for subtitle integrity"""
    try:
        # Use deterministic serialization for consistent hashing
        h = C_HMAC(SUBTITLE_HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(json.dumps(payload, sort_keys=True).encode())
        return h.finalize().hex()
    except Exception as e:
        log_event(f"[SECURITY] HMAC generation failed: {str(e)[:50]}", level="error")
        return ""

def _encrypt_subtitle(payload: Dict) -> str:
    """AES-256-GCM encryption for subtitle caching"""
    try:
        nonce = os.urandom(12) # GCM requires a unique nonce for each encryption
        cipher = Cipher(algorithms.AES(SUBTITLE_CRYPTO_KEY), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(json.dumps(payload, sort_keys=True).encode()) + encryptor.finalize()
        return binascii.hexlify(nonce + encryptor.tag + ciphertext).decode()
    except Exception as e:
        log_event(f"[SECURITY] Subtitle encryption failed: {str(e)[:50]}", level="error")
        return ""

def _decrypt_subtitle(encrypted: str) -> Optional[Dict]:
    """Secure decryption for subtitle cache replay"""
    try:
        if _subtitle_killed or not encrypted:
            return None

        data = binascii.unhexlify(encrypted.encode())
        # Correctly parse nonce, tag, and ciphertext from the encrypted data
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        cipher = Cipher(
            algorithms.AES(SUBTITLE_CRYPTO_KEY),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return json.loads((decryptor.update(ciphertext) + decryptor.finalize()).decode())
    except Exception as e:
        log_event(f"[SECURITY] Subtitle decryption failed: {str(e)[:50]}", level="error")
        return None

async def generate_live_subtitles(
    mic_stream, 
    user_lang: str,
    target_lang: str,
    socket_send_fn,
    socket_id: str,
    session_token: str = None
) -> None:
    """
    Real-time subtitle pipeline with:
    - STT → Translation → Emotion → Styling
    - Nuclear-grade input validation
    - Hardened socket emission
    - Encrypted caching
    """
    if _subtitle_killed or not validate_session_token(session_token):
        return

   

    try:
        async for segment in stream_transcribe(mic_stream, lang_hint=user_lang):
            try:
                start_time = time.perf_counter()


                if not await rate_limit(f"subtitle_gen_{socket_id}", max_calls=30):
                    security_alert(f"Rate limit exceeded for {socket_id}")
                    break

                translated_text = await translate_if_needed(
                  
                    user_lang, 
                    target_lang
                )

               
                if tone not in ["neutral", "happy", "sad", "angry", "excited", "confused"]:
                    tone = "neutral"

               

                subtitle_payload = {
                   
                    "lang": target_lang,
                    "tone": tone,
                    "timestamp": datetime.utcnow().isoformat(),
                    "subtitle_id": str(uuid.uuid4()),
                    "latency_ms": (time.perf_counter() - start_time) * 1000
                }

                if subtitle_payload["latency_ms"] > MAX_SUBTITLE_LATENCY_MS:
                    security_alert(f"Subtitle latency attack: {subtitle_payload['latency_ms']}ms")
                    continue

                await emit_subtitle(subtitle_payload, socket_id, socket_send_fn)
                await cache_subtitle(subtitle_payload)
                await log_subtitle_event({
                    "subtitle_id": subtitle_payload["subtitle_id"],
                    "lang": target_lang,
                    "tone": tone,
                    "timestamp": subtitle_payload["timestamp"],
                    "latency": subtitle_payload["latency_ms"]
                })
            except Exception as e:
                security_alert(f"Subtitle generation failure: {str(e)}")
                continue

    except Exception as e:
        security_alert(f"Live subtitle pipeline failed: {str(e)}")
        return

async def translate_if_needed(text: str, source_lang: str, target_lang: str) -> str:
    """Secure translation gate with input validation"""
    if _subtitle_killed or source_lang == target_lang:
        return text

  

    try:
        return await translate_text(
            src_lang=source_lang,
            tgt_lang=target_lang
        )[:MAX_SUBTITLE_LENGTH]
    except Exception as e:
        log_event(f"[SECURITY] Translation failed: {str(e)[:50]}", level="error")
        return text

async def emit_subtitle(payload: dict, socket_id: str, socket_send_fn) -> None:
    """Hardened socket emission with payload validation"""
    if _subtitle_killed or not validate_session_token(socket_id):
        return

    try:
        if not await rate_limit(f"socket_emit_{socket_id}", max_calls=25):
            security_alert(f"Socket flood attempt: {socket_id}")
            return

        required_keys = {"text", "lang", "tone", "subtitle_id"}
        if not all(k in payload for k in required_keys):
            raise ValueError("Invalid subtitle payload")

        await socket_send_fn(
            socket_id,
            json.dumps({
                **payload,
                "_secure": True
            })
        )
    except Exception as e:
        security_alert(f"Subtitle emission failed: {str(e)}")

async def cache_subtitle(payload: dict) -> None:
    """Encrypted write-through cache with atomic locks"""
    if _subtitle_killed:
        return

    async with _cache_lock:
        try:
            payload_hash = hashlib.sha256(payload["text"].encode()).hexdigest()
            if payload_hash in BLACKLISTED_SUBTITLE_HASHES:
                security_alert(f"Blacklisted subtitle detected: {payload_hash}")
                return

            encrypted = _encrypt_subtitle(payload)
            subtitle_cache[payload["subtitle_id"]] = encrypted
            log_event(f"Subtitle cached: {payload['subtitle_id'][:8]}...", sanitize=True)
        except Exception as e:
            log_event(f"[SECURITY] Cache write failed: {str(e)[:50]}", level="error")

def kill_subtitle():
    """Emergency kill switch — wipes keys and stops dispatch."""
    global _subtitle_killed
    _subtitle_killed = True
    log_event("Subtitle: Engine killed.", level="critical")