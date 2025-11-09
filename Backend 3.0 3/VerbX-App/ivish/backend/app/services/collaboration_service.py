# 🔒 Final, Secure Collaboration Engine for Ivish AI
# 🚀 Refactored Code

import os
import time
import uuid
import asyncio
import logging
import hashlib
import subprocess
import json
import hmac
from typing import Dict, Optional, Any, List, Union
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import HTTPException

# Corrected Internal imports
from ..utils.logger import log_event
from ..utils.cache import redis_client
from ..utils.rate_meter import rate_meter
from ....ai_models.translation.mt_translate import translate_text
from ....ai_models.emotion.emotion_handler import detect_emotion
from ....ai_models.ivish.ivish_memory import update_shared_memory
from ....security.blockchain.zkp_handler import validate_token
from ....realtime.socketio.manager import broadcast_to_room
from ....security.blockchain.blockchain_utils import log_collab_event
from ....security.intrusion_prevention.counter_response import blackhole_response_action, rotate_endpoint
from ....ai_models.translation.dialect_adapter import detect_language

# Security constants
MAX_MESSAGE_LENGTH = int(os.getenv("MAX_MESSAGE_LENGTH", "2000"))
MAX_AUDIO_CHUNK_SIZE = int(os.getenv("MAX_AUDIO_CHUNK_SIZE", "2097152"))
MAX_SESSION_USERS = int(os.getenv("MAX_SESSION_USERS", "25"))
MAX_SESSION_DURATION = int(os.getenv("MAX_SESSION_DURATION", "3600"))
BLACKHOLE_DELAY = int(os.getenv("BLACKHOLE_DELAY_SEC", "60"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
COLLAB_AES_KEY = os.getenv("COLLAB_AES_KEY", None)
if not COLLAB_AES_KEY:
    raise RuntimeError("COLLAB_AES_KEY not found in environment.")
COLLAB_AES_KEY = COLLAB_AES_KEY.encode()

COLLAB_HMAC_KEY = os.getenv("COLLAB_HMAC_KEY", None)
if not COLLAB_HMAC_KEY:
    raise RuntimeError("COLLAB_HMAC_KEY not found in environment.")
COLLAB_HMAC_KEY = COLLAB_HMAC_KEY.encode()

COLLAB_USER_SALT = os.getenv("COLLAB_USER_SALT", None)
if not COLLAB_USER_SALT:
    raise RuntimeError("COLLAB_USER_SALT not found in environment.")
COLLAB_USER_SALT = COLLAB_USER_SALT.encode()


logger = logging.getLogger(__name__)

class CollaborationService:
    """
    Provides secure, auditable, and emotionally aware multi-user collaboration.
    """
    async def create_session(self, host_id: str, zkp_proof: str) -> Dict[str, Any]:
        """
        Secure session creation with ZKP validation and ephemeral token generation.
        """
        if not validate_token(host_id, zkp_proof):
            raise HTTPException(status_code=403, detail="Access denied")

        session_id = str(uuid.uuid4())
        zkp_token = hashlib.sha256(f"{host_id}{session_id}{os.urandom(16)}".encode()).hexdigest()

        try:
            # Using Redis for scalable session storage
            session_key = f"collab_session:{session_id}"
            session_data = {
                "host_id": host_id,
                "token": zkp_token,
                "users": [host_id],
                "created_at": time.time()
            }
            redis_client.setex(session_key, MAX_SESSION_DURATION, json.dumps(session_data))
            
            await log_collab_event({
                "action": "session_created",
                "host": self._hash_user_id(host_id),
                "session_id": session_id,
                "timestamp": time.time()
            })

            return {
                "status": "success",
                "session_id": session_id,
                "token": zkp_token,
                "timestamp": time.time()
            }
        except Exception as e:
            logger.error(f"[COLLAB] Session creation failed: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Session creation failed")

    async def join_session(self, user_id: str, session_id: str, token: str) -> Dict[str, Any]:
        """
        Secure session joining with token validation and user limit enforcement.
        """
        if await rate_meter.track_call(user_id, source="collab_join"):
            raise HTTPException(status_code=429, detail="Too many requests")

        if not validate_token(user_id, token):
            raise HTTPException(status_code=403, detail="Invalid token")

        session_key = f"collab_session:{session_id}"
        session_data_raw = redis_client.get(session_key)
        if not session_data_raw:
            raise HTTPException(status_code=404, detail="Session does not exist")

        session_data = json.loads(session_data_raw)
        if len(session_data.get("users", [])) >= MAX_SESSION_USERS:
            raise HTTPException(status_code=403, detail="Session full")

        try:
            if user_id not in session_data["users"]:
                session_data["users"].append(user_id)
            
            new_token = hashlib.sha256(f"{user_id}{session_id}{os.urandom(16)}".encode()).hexdigest()
            session_data["token"] = new_token
            redis_client.setex(session_key, MAX_SESSION_DURATION, json.dumps(session_data))
            
            return {
                "status": "joined",
                "session_id": session_id,
                "token": new_token,
                "users": session_data["users"],
                "timestamp": time.time()
            }
        except Exception as e:
            logger.error(f"[COLLAB] Session join failed: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Session join failed")

    async def broadcast_message(self, user_id: str, session_id: str, message: str, src_lang: str = "auto", target_lang: str = "en") -> Dict[str, Any]:
        """
        Secure message broadcast with translation and secure logging.
        """
        if await rate_meter.track_call(user_id, source="collab_broadcast"):
            raise HTTPException(status_code=429, detail="Too many requests")
            
        session_key = f"collab_session:{session_id}"
        session_data_raw = redis_client.get(session_key)
        if not session_data_raw or user_id not in json.loads(session_data_raw).get("users", []):
            raise HTTPException(status_code=403, detail="Not in session")

        if len(message) > MAX_MESSAGE_LENGTH:
            raise HTTPException(status_code=400, detail="Message exceeds length limit")

        try:
            detected_lang = await detect_language(message)
            src_lang = src_lang if src_lang != "auto" else detected_lang

            translated = message
            if src_lang != target_lang:
                translated = await translate_text(message, src=src_lang, tgt=target_lang)
            
            emotion = await detect_emotion(message)

            await update_shared_memory(session_id, user_id, message, emotion)

            secure_data = {
                "from": user_id,
                "message": translated,
                "original": message,
                "emotion": emotion,
                "timestamp": time.time(),
                "session_id": session_id,
                "integrity": self._generate_integrity_tag({
                    "user": user_id,
                    "message": translated,
                    "session": session_id
                })
            }

            await broadcast_to_room(session_id, secure_data)
            await log_collab_event({
                "action": "message_broadcast",
                "user": self._hash_user_id(user_id),
                "session": session_id,
                "message_hash": hashlib.sha256(message.encode()).hexdigest(),
                "emotion": emotion,
                "timestamp": time.time()
            })

            return {"status": "success", "data": secure_data}
        except Exception as e:
            logger.error(f"[COLLAB] Broadcast failed: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Broadcast failed")

    async def end_session(self, session_id: str, user_token: str, zk_proof: str) -> Dict[str, Any]:
        """
        Secure session termination with ZKP validation and auto-wipe of data.
        """
        if not validate_token(user_token, zk_proof):
            raise HTTPException(status_code=403, detail="Access denied")

        session_key = f"collab_session:{session_id}"
        session_data_raw = redis_client.get(session_key)
        if not session_data_raw:
            raise HTTPException(status_code=404, detail="Session not found")

        try:
            session_data = json.loads(session_data_raw)
            redis_client.delete(session_key)

            await log_collab_event({
                "action": "session_terminated",
                "session": session_id,
                "timestamp": time.time(),
                "host": session_data.get("host_id")
            })

            # Securely wipe data with a non-blocking subprocess call
            await asyncio.create_subprocess_exec("shred", "-u", f"/tmp/ivish_collab_{session_id}*")
            return {"status": "ended", "session_id": session_id}
        except Exception as e:
            logger.error(f"[COLLAB] Session termination failed: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Session termination failed")

    def _generate_integrity_tag(self, payload: Dict[str, Any]) -> str:
        """Cryptographic tag for collaboration validation."""
        h = hmac.HMAC(COLLAB_HMAC_KEY, hashes.SHA256(), backend=default_backend())
        # Use a canonical representation to ensure consistent hashing
        canonical_data = json.dumps(payload, sort_keys=True).encode()
        h.update(canonical_data)
        return h.finalize().hex()
    
    def _hash_user_id(self, user_id: str) -> str:
        """PBKDF2-HMAC-SHA512 user hashing."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=COLLAB_USER_SALT,
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(user_id.encode()).hex()

# Singleton with rate limit
collaboration_service = CollaborationService()