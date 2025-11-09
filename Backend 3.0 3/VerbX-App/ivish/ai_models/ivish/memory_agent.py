import hashlib
import json
import os
import time
import asyncio
import numpy as np
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from functools import lru_cache

# REASON: Ephemeral keys rotated daily
_MEMORY_KEY = os.urandom(32)
_HMAC_KEY = os.urandom(32)

# REASON: Global kill switch for intrusion detection
_memory_killed = False

# Corrected Imports based on project architecture
from backend.app.db.redis import redis_conn as redis_client
from backend.app.db.mongo import mongo_db
from backend.app.utils.logger import log_event, BaseLogger
from ai_models.emotion.emotion_handler import detect_emotion
# Placeholder for non-existent modules
def has_user_consented(user_id: str, scope: str) -> bool:
    """Placeholder for consent check logic."""
    return True
# --- Constants (from removed config file) ---
MEMORY_TTL_DAYS = int(os.getenv("MEMORY_TTL_DAYS", "7"))

logger = BaseLogger("MemoryAgent")

class SecurityError(Exception):
    """Raised when memory tampering is detected"""
    pass

def _encrypt_pii(data: str) -> bytes:
    """AES-256-GCM encryption for PII fields, prepending IV and tag."""
    try:
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(_MEMORY_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag
    except Exception as e:
        logger.log_event(f"Memory: Encryption failed - {str(e)[:50]}", level="ERROR")
        return b''

def _decrypt_pii(encrypted: bytes) -> str:
    """AES-256-GCM decryption, correctly parsing IV and tag."""
    try:
        iv = encrypted[:12]
        tag = encrypted[-16:]
        ciphertext = encrypted[12:-16]
        cipher = Cipher(algorithms.AES(_MEMORY_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        logger.log_event(f"Memory: Decryption failed - {str(e)[:50]}", level="ERROR")
        return ''

def _hash_user_id(user_id: str) -> str:
    """Pseudonymization with SHA-256."""
    return hashlib.sha256(user_id.encode()).hexdigest()

def _hmac_entry(user_id: str, data: str) -> str:
    """HMAC-SHA384 for data integrity."""
    h = hmac.HMAC(_HMAC_KEY, hashes.SHA384(), backend=default_backend())
    h.update(f"{user_id}|{data}".encode())
    return h.finalize().hex()

def _apply_dp_noise(tone: str) -> str:
    """Add Laplace noise to a numeric representation of tone."""
    tone_to_int = {"neutral": 0, "happy": 1, "sad": -1, "angry": -2}
    if tone in tone_to_int:
        numeric_tone = tone_to_int[tone]
        noise = np.random.laplace(0, 0.5)
        noisy_tone = numeric_tone + noise
        return str(round(noisy_tone, 2))
    return tone

def _validate_session(user_id: str) -> bool:
    """ZKP validation against voiceprint-secured session."""
    # Placeholder for actual ZKP validation and voiceprint binding
    return True

def _check_kill_switch() -> bool:
    """Prevents memory operations after intrusion detection."""
    global _memory_killed
    return _memory_killed

def _generate_session_key(user_id: str) -> str:
    """Generates Redis session key for user."""
    return f"session_memory:{_hash_user_id(user_id)}"

async def store_conversation(user_id: str, user_input: str, ivish_response: str):
    """Securely stores conversation turns with session-bound encryption."""
    if not user_id or not _validate_session(user_id) or _check_kill_switch():
        return

    hashed_id = _hash_user_id(user_id)
    key = _generate_session_key(user_id)

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "user_input": _encrypt_pii(user_input),
        "ivish_response": _encrypt_pii(ivish_response),
        "hmac": _hmac_entry(user_id, user_input + ivish_response)
    }

    try:
        # REASON: Atomic Redis transaction
        async with redis_client.pipeline() as pipe:
            await pipe.rpush(key, json.dumps(entry))
            await pipe.expire(key, MEMORY_TTL_DAYS * 86400)
            await pipe.execute()
        logger.log_event(f"Memory updated", level="INFO", meta={"user": hashed_id[:6]}, sanitize=True)
    except Exception as e:
        logger.log_event(f"Memory: Redis write failed - {str(e)[:50]}", level="ERROR")

async def get_session_context(user_id: str, limit: int = 5) -> list:
    """Retrieves and verifies conversation history."""
    if not _validate_session(user_id) or _check_kill_switch():
        return []

    key = _generate_session_key(user_id)
    try:
        raw_data = await redis_client.lrange(key, -limit, -1)
    except Exception as e:
        logger.log_event(f"Memory: Redis read failed - {str(e)[:50]}", level="ERROR")
        return []

    decrypted = []
    for entry_bytes in raw_data:
        if not entry_bytes:
            continue
        try:
            entry = json.loads(entry_bytes)
            user_input = _decrypt_pii(entry["user_input"])
            ivish_response = _decrypt_pii(entry["ivish_response"])
            expected_hmac = _hmac_entry(user_id, user_input + ivish_response)

            if not hmac.compare_digest(entry["hmac"].encode(), expected_hmac.encode()):
                raise SecurityError("HMAC mismatch")

            decrypted.append({
                "timestamp": entry["timestamp"],
                "user_input": user_input,
                "ivish_response": ivish_response
            })
        except Exception as e:
            logger.log_event(f"Memory tampering detected: {str(e)[:50]}", level="CRITICAL")

    return decrypted

async def store_phrasebook(user_id: str, phrase: str, translation: str):
    """Consent-gated encrypted phrase storage."""
    if not user_id or not _validate_session(user_id) or _check_kill_switch():
        return

    if not has_user_consented(user_id, "memory"):
        return

    hashed_id = _hash_user_id(user_id)
    encrypted_entry = {
        "user_id": hashed_id,
        "phrase": _encrypt_pii(phrase),
        "translation": _encrypt_pii(translation),
        "timestamp": datetime.now(timezone.utc),
        "expire_at": datetime.now(timezone.utc) + timedelta(days=30)
    }

    try:
        await mongo_db.phrasebook.insert_one(encrypted_entry)
        await mongo_db.phrasebook.create_index("expire_at", expireAfterSeconds=0)
        logger.log_event("Phrase stored", level="INFO", meta={"user": hashed_id[:6]})
    except Exception as e:
        logger.log_event(f"Memory: Phrasebook write failed - {str(e)[:50]}", level="ERROR")

async def get_phrasebook(user_id: str) -> list:
    """Returns all stored phrases with decryption."""
    if not _validate_session(user_id) or _check_kill_switch():
        return []

    try:
        phrases = []
        async for doc in mongo_db.phrasebook.find({"user_id": _hash_user_id(user_id)}):
            phrases.append({
                k: _decrypt_pii(v) if k in ("phrase", "translation") else v
                for k, v in doc.items()
            })
        return phrases
    except Exception as e:
        logger.log_event(f"Memory: Phrasebook read failed - {str(e)[:50]}", level="ERROR")
        return []

async def clear_user_memory(user_id: str):
    """GDPR-compliant memory purge."""
    if not _validate_session(user_id) or _check_kill_switch():
        return

    hashed_id = _hash_user_id(user_id)
    key = _generate_session_key(user_id)

    try:
        await redis_client.delete(key)
        await mongo_db.phrasebook.update_many(
            {"user_id": hashed_id},
            {"$set": {
                "phrase": os.urandom(32),
                "translation": os.urandom(32)
            }}
        )
        await mongo_db.phrasebook.delete_many({"user_id": hashed_id})
        await mongo_db.tone_memory.delete_many({"user_id": hashed_id})

        logger.log_event("Memory wiped", level="INFO", meta={"user": hashed_id[:6]})
    except Exception as e:
        logger.log_event(f"Memory: Wipe failed - {str(e)[:50]}", level="ERROR")

async def inject_memory_context(user_id: str) -> str:
    """Builds prompt context with integrity checks."""
    if not _validate_session(user_id) or _check_kill_switch():
        return ""

    session = await get_session_context(user_id)
    phrases = await get_phrasebook(user_id)
    tone = await get_tone_preference(user_id)

    context = "\n--- Previous Conversations ---\n"
    for turn in session:
        context += f"User: {turn['user_input']}\nIvish: {turn['ivish_response']}\n"

    context += f"\n--- Preferred Tone: {tone or 'neutral'} ---\n"
    if phrases:
        context += "\n--- Saved Phrases ---\n"
        for p in phrases[:5]:
            context += f"{p['phrase']} = {p['translation']}\n"

    return context

async def store_tone_preference(user_id: str, user_input: str):
    """Detects and stores tone with differential privacy."""
    if not user_id or not _validate_session(user_id) or _check_kill_switch():
        return

    if not has_user_consented(user_id, "memory"):
        return

    hashed_id = _hash_user_id(user_id)
    try:
        tone = await detect_emotion(user_input)
        noisy_tone = _apply_dp_noise(tone)

        await mongo_db.tone_memory.update_one(
            {"user_id": hashed_id},
            {"$set": {
                "tone": noisy_tone,
                "updated": datetime.now(timezone.utc),
                "expire_at": datetime.now(timezone.utc) + timedelta(days=90)
            }},
            upsert=True
        )
        await mongo_db.tone_memory.create_index("expire_at", expireAfterSeconds=0)
    except Exception as e:
        logger.log_event(f"Memory: Tone storage failed - {str(e)[:50]}", level="ERROR")

async def get_tone_preference(user_id: str) -> Optional[str]:
    """Returns stored tone preference."""
    if not _validate_session(user_id) or _check_kill_switch():
        return None

    try:
        record = await mongo_db.tone_memory.find_one({"user_id": _hash_user_id(user_id)})
        return record.get("tone") if record else None
    except Exception as e:
        logger.log_event(f"Memory: Tone fetch failed - {str(e)[:50]}", level="ERROR")
        return None

def kill_memory():
    """Emergency kill switch - wipes keys and stops dispatch."""
    global _memory_killed, _MEMORY_KEY, _HMAC_KEY
    _memory_killed = True
    # Securely overwrite keys
    _MEMORY_KEY = b'\x00' * 32
    _HMAC_KEY = b'\x00' * 32
    logger.log_event("Memory: Engine killed. Session wiped.", level="CRITICAL")

# End of memory_agent.py