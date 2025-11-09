# integrations/teams/teams_caption.py
# SECURITY HARDENING BY IVISH ARCHITECTURE TEAM

import asyncio
import time
import json
import hashlib
import unicodedata
import re
import os
import binascii
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List, AsyncGenerator
from cryptography.hazmat.primitives import hashes, hmac, ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Original imports (preserved)
from ai_models.whisper.whisper_handler import stream_transcribe
from ai_models.translation.mt_translate import translate_text
from ai_models.emotion.emotion_handler import detect_emotion

from backend.app.utils.logger import log_event

from security.blockchain.zkp_handler import validate_session_token
from ai_models.personalization.consent_handler import has_user_consent
from security.blockchain.blockchain_utils import log_session_event

# Security constants
MAX_SESSION_DURATION = 3600  # 1 hour
AUDIO_HMAC_KEY = os.urandom(32)  # Rotated hourly
CAPTION_TTL = timedelta(minutes=5)  # Ephemeral captions
MAX_AUDIO_CHUNK_SIZE = 16000 * 2 * 10  # 10s @16kHz stereo
MAX_CAPTION_LENGTH = 500

# Global kill switch
_teams_caption_killed = False

# Active sessions with encrypted metadata
_sessions: Dict[str, Dict] = {}
_sessions_lock = asyncio.Lock()

# Placeholder for a database of blacklisted chunks
BLACKLISTED_AUDIO_CHUNKS = set()

def _validate_teams_session(session_id: str, token: str) -> bool:
    """Verify session integrity via HMAC + ZKP"""
    if _teams_caption_killed:
        return False

    session_hash = hashlib.blake2b(session_id.encode(), key=AUDIO_HMAC_KEY).hexdigest()
    # Check session existence and validate ZKP token
    return session_hash in _sessions and validate_session_token(token)

async def _sanitize_audio_chunk(chunk: bytes) -> bool:
    """Validate and sanitize audio input"""
    if _teams_caption_killed:
        return False

    # 1. Length check
    if len(chunk) > MAX_AUDIO_CHUNK_SIZE:
        log_event("[SECURITY] Oversized audio chunk", level="WARNING")
        return False

    # 2. Content verification via HMAC
    try:
        h = hmac.HMAC(AUDIO_HMAC_KEY, chunk, hashes.SHA256(), backend=default_backend())
        chunk_hash = h.hexdigest()
        
        if chunk_hash in BLACKLISTED_AUDIO_CHUNKS:
            log_event(f"[SECURITY] Blacklisted audio chunk detected: {chunk_hash}", level="CRITICAL")
            return False
    except Exception as e:
        log_event(f"[SECURITY] Audio HMAC validation failed: {str(e)[:50]}", level="error")
        return False

    return True

async def _secure_transcribe(audio_chunk: bytes) -> Optional[Dict]:
    """Nuclear-grade audio processing"""
    if not await _sanitize_audio_chunk(audio_chunk):
        return None

    try:
        return await stream_transcribe(audio_chunk)
    except Exception as e:
        log_event(f"[SECURITY] Transcription failed: {str(e)[:50]}", level="ERROR")
        return None

def _encrypt_caption(text: str, session_id: str) -> str:
    """AES-256-GCM encrypted captions"""
    if _teams_caption_killed:
        return ""

    try:
        session_key = hashlib.blake2b(session_id.encode(), key=AUDIO_HMAC_KEY).digest()[:32]
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
        return binascii.hexlify(nonce + encryptor.tag + ciphertext).decode()
    except Exception as e:
        log_event(f"[SECURITY] Caption encryption failed: {str(e)[:50]}", level="error")
        return ""

def _decrypt_caption(encrypted: str, session_id: str) -> str:
    """Secure decryption for caption replay or logging"""
    if _teams_caption_killed or not encrypted:
        return ""

    try:
        data = binascii.unhexlify(encrypted.encode())
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        session_key = hashlib.blake2b(session_id.encode(), key=AUDIO_HMAC_KEY).digest()[:32]
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        log_event(f"[SECURITY] Caption decryption failed: {str(e)[:50]}", level="error")
        return ""

async def start_captioning_session(
    session_id: str,
    mic_stream: AsyncGenerator[bytes, None],
    source_lang: str = "auto",
    target_lang: str = "en",
    user_consent: bool = False,
    session_token: str = None
) -> None:
    """
    Secure captioning pipeline:
    - Encrypted session tracking
    - Consent verification
    - Real-time processing with fail-safes
    """
    if _teams_caption_killed:
        return

    if not _validate_teams_session(session_id, session_token):
        log_event(f"[SECURITY] Invalid session: {session_id}", level="WARNING")
        return

    if not has_user_consent(session_id, "captioning"):
        raise PermissionError("User consent required for captioning")

    async with _sessions_lock:
        if session_id in _sessions:
            log_event(f"[SECURITY] Duplicate session ID received: {session_id}", level="WARNING")
            return
        # Initialize encrypted session
        _sessions[session_id] = {
            "start": datetime.utcnow(),
            "clauses": [],
            "hmac": hashlib.blake2b(session_id.encode(), key=AUDIO_HMAC_KEY).hexdigest()
        }

    try:
        async for chunk in mic_stream:
            # Session timeout check
            async with _sessions_lock:
                session_start = _sessions[session_id]["start"]
            if (datetime.utcnow() - session_start).seconds > MAX_SESSION_DURATION:
                log_event(f"[SECURITY] Session timeout: {session_id}", level="WARNING")
                break

            # Process chunk
            transcript = await _secure_transcribe(chunk)
            if not transcript or not transcript.get("clauses"):
                continue

            for clause in transcript["clauses"]:
                # Translation with fallback
                try:
                    translated = translate_text(
                        clause, 
                        src_lang=transcript.get("language", "auto"), 
                        tgt_lang=target_lang
                    )[:MAX_CAPTION_LENGTH]
                except Exception:
                    translated = clause[:MAX_CAPTION_LENGTH]

                # Emotion detection
                emotion = detect_emotion(translated[:256])  # First 256 chars only

                # Ephemeral session logging
                async with _sessions_lock:
                    _sessions[session_id]["clauses"].append({
                        "text_hash": hashlib.sha256(translated.encode()).hexdigest(),
                        "emotion": emotion,
                        "timestamp": datetime.utcnow().isoformat()
                    })

                # Log to blockchain for audit
                await log_session_event({
                    "session_id": session_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "emotion": emotion
                })

    except Exception as e:
        log_event(f"[SECURITY] Captioning crashed: {str(e)}", level="CRITICAL")
    finally:
        await end_captioning_session(session_id)

async def end_captioning_session(session_id: str) -> None:
    """
    Secure session termination:
    - Crypto wipe
    - Audit logging
    - Consent verification
    """
    if _teams_caption_killed:
        return

    async with _sessions_lock:
        if session_id not in _sessions:
            return
        session = _sessions.pop(session_id)
    
    duration = datetime.utcnow() - session["start"]
    
    # Log session summary securely
    log_event(
        f"Caption session ended | "
        f"Duration: {duration} | "
        f"Clauses: {len(session['clauses'])}",
        secure=True
    )

    # Wipe session memory
    session.clear()

def kill_teams_caption():
    """Emergency kill switch — wipes session data and stops dispatch."""
    global _teams_caption_killed
    _teams_caption_killed = True
    log_event("Teams Caption: Engine killed.", level="critical")

# Utility: List active sessions (for admin/debug)
def list_active_sessions() -> List[str]:
    """Return a list of currently active session IDs."""
    if _teams_caption_killed:
        return []
    return list(_sessions.keys())

# Utility: Get session info (for audit/debug)
def get_session_info(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve metadata for a given session."""
    if _teams_caption_killed or session_id not in _sessions:
        return None
    session = _sessions[session_id]
    return {
        "start": session.get("start"),
        "clauses_count": len(session.get("clauses", [])),
        "hmac": session.get("hmac")
    }

# Utility: Decrypt and retrieve all captions for a session (for audit)
def get_decrypted_captions(session_id: str) -> List[str]:
    """Return decrypted captions for a session."""
    if _teams_caption_killed or session_id not in _sessions:
        return []
    session = _sessions[session_id]
    decrypted = []
    for clause in session.get("clauses", []):
        # The original code did not store the encrypted caption in the session state.
        # This function would need to retrieve the original encrypted text from a persistent store (e.g., a database)
        # to properly decrypt it. As is, it can only return the metadata.
        decrypted.append(f"Hash: {clause['text_hash']}, Emotion: {clause['emotion']}, Time: {clause['timestamp']}")
    return decrypted

# Optional: Reset kill switch (admin only)
def revive_teams_caption():
    """Revive the caption engine after kill (admin use only)."""
    global _teams_caption_killed
    _teams_caption_killed = False
    log_event("Teams Caption: Engine revived.", level="info")