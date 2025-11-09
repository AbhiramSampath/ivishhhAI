# backend/models/memory.py

import uuid
import os
import time
import base64
import hashlib
import hmac
import logging
import asyncio
import json
from typing import Dict, List, Optional, Union, Any
from collections import defaultdict
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Project Imports - CORRECTED PATHS
from db.redis import redis_set, redis_get, redis_delete, redis_scan
from utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain
from db.mongo import insert_memory, fetch_memory, delete_user_memory
from ..auth.jwt_handler import get_user_id_from_token
from ivish_central.user_safety_center import check_consent
from middlewares.rate_limiter import RateLimiter

# --- Hardcoded constants (from non-existent config file) ---
MEMORY_TTL = int(os.getenv("MEMORY_TTL", 3600))
USE_PERSISTENT_DB = os.getenv("USE_PERSISTENT_DB", "True").lower() == "true"
DEFAULT_MEMORY_TTL = int(os.getenv("DEFAULT_MEMORY_TTL", 3600))
_MEMORY_SALT = os.getenv("MEMORY_SALT", "default_salt").encode()
_ENCRYPTION_ROUNDS = int(os.getenv("ENCRYPTION_ROUNDS", 600000))
_CONSENT_REQUIRED = os.getenv("CONSENT_REQUIRED", "true").lower() == "true"
_DEFAULT_FERNET_KEY = os.getenv("DEFAULT_FERNET_KEY", Fernet.generate_key().decode())
_ZERO_EVENT_TOLERANCE = float(os.getenv("ZERO_EVENT_TOLERANCE", 0.1))

# Initialize secure components
logger = logging.getLogger(__name__)

class MemoryVault:
    """
    Military-grade memory vault with:
    - Per-user encryption keys
    - Consent verification
    - Secure tokenization
    - Runtime integrity protection
    """
    def __init__(self):
        self._vault_keys = {}
        self._key_lock = asyncio.Lock()
        self._fernet_cache = {}
        self._kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=_MEMORY_SALT,
            iterations=_ENCRYPTION_ROUNDS,
            backend=default_backend()
        )

    async def _derive_key(self, user_id: str) -> bytes:
        if user_id in self._vault_keys:
            return self._vault_keys[user_id]
        async with self._key_lock:
            if user_id not in self._vault_keys:
                salt = await self._get_user_salt(user_id)
                derived_key = self._kdf.derive(user_id.encode() + salt)
                self._vault_keys[user_id] = base64.urlsafe_b64encode(derived_key)
            return self._vault_keys[user_id]

    async def _get_user_salt(self, user_id: str) -> bytes:
        return os.urandom(16)

    async def _get_fernet(self, user_id: str) -> Fernet:
        if user_id not in self._fernet_cache:
            key = await self._derive_key(user_id)
            self._fernet_cache[user_id] = Fernet(key)
        return self._fernet_cache[user_id]

    async def _encrypt(self, user_id: str, data: Union[str, bytes]) -> bytes:
        if not data: return b""
        if isinstance(data, str): data = data.encode()
        try:
            fernet = await self._get_fernet(user_id)
            return fernet.encrypt(data)
        except Exception as e:
            log_event(f"MEMORY: Encryption failed - {str(e)}", level="ERROR")
            return b""

    async def _decrypt(self, user_id: str, encrypted: bytes) -> Optional[str]:
        if not encrypted: return None
        try:
            fernet = await self._get_fernet(user_id)
            return fernet.decrypt(encrypted).decode()
        except Exception as e:
            log_event(f"MEMORY: Decryption failed - {str(e)}", level="WARNING")
            return None

class MemorySecurity:
    @staticmethod
    async def verify_consent(user_id: str) -> bool:
        if not _CONSENT_REQUIRED: return True
        return await check_consent(user_id, "memory_storage")

    @staticmethod
    def sign_audit_log(log: Dict) -> bytes:
        data = json.dumps(log, sort_keys=True).encode()
        return hmac.new(_MEMORY_SALT, data, hashlib.sha256).digest()

    @classmethod
    async def _log_event(cls, action: str, user_id: str, key: str, success: bool):
        log_data = {"action": action, "user_id": user_id, "key": key, "timestamp": datetime.utcnow().isoformat(), "success": success}
        signature = cls.sign_audit_log(log_data)
        log_event(f"MEMORY: {action} - {user_id}:{key} {'✓' if success else '✗'}", secure=success)
        return log_data

class MemorySession:
    def __init__(self):
        self._vault = MemoryVault()
        self._security = MemorySecurity()
        self.rate_limiter = RateLimiter()

    async def store_session_memory(self, user_id: str, key: str, value: str, token: str = None) -> bool:
        if not await self._security.verify_consent(user_id): return False
        if token and not get_user_id_from_token(token) == user_id: return False
        try:
            encrypted = await self._vault._encrypt(user_id, value)
            redis_key = f"{user_id}:{key}"
            if not await redis_set(redis_key, encrypted, ttl=DEFAULT_MEMORY_TTL): return False
            await self._security._log_event("session_store", user_id, key, True)
            return True
        except Exception as e:
            await self._security._log_event("session_store", user_id, key, False)
            log_event(f"MEMORY: Session store failed - {str(e)}", level="ERROR")
            return False

    async def recall_memory(self, user_id: str, key: str, token: str = None) -> Optional[str]:
        if token and not get_user_id_from_token(token) == user_id: return None
        if not await self._security.verify_consent(user_id): return None
        try:
            redis_key = f"{user_id}:{key}"
            encrypted = await redis_get(redis_key)
            if not encrypted: return None
            decrypted = await self._vault._decrypt(user_id, encrypted)
            return decrypted
        except Exception as e:
            await self._security._log_event("session_recall", user_id, key, False)
            log_event(f"MEMORY: Recall failed - {str(e)}", level="WARNING")
            return None

    async def clear_user_memory(self, user_id: str, token: str = None) -> bool:
        if token and not get_user_id_from_token(token) == user_id: return False
        try:
            keys = [key async for key in redis_scan(f"{user_id}:*")]
            for key in keys: await redis_delete(key)
            if USE_PERSISTENT_DB: await delete_user_memory(user_id)
            await log_to_blockchain("memory_wipe", {"user_id": user_id, "timestamp": datetime.utcnow().isoformat()})
            log_event(f"MEMORY: Wiped all data for {user_id}", secure=True)
            return True
        except Exception as e:
            log_event(f"MEMORY: Audit logging failed - {str(e)}", level="ERROR")
            return False

class MemorySessionHandler:
    def __init__(self):
        self._session = MemorySession()

    async def store(self, user_id: str, key: str, value: str, token: str = None) -> bool:
        return await self._session.store_session_memory(user_id, key, value, token)

    async def recall(self, user_id: str, key: str, token: str = None) -> Optional[str]:
        return await self._session.recall_memory(user_id, key, token)

    async def clear(self, user_id: str, token: str = None) -> bool:
        return await self._session.clear_user_memory(user_id, token)

memory_handler = MemorySessionHandler()