# backend/db/redis.py
# 🔒 Nuclear-Grade Redis Access Layer | Zero-Trust Architecture | GDPR-Compliant

import json
import time
import hashlib
import unicodedata
import re
import os
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List, Union
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from redis.asyncio import Redis as AsyncRedis
from redis.exceptions import RedisError, ConnectionError as RedisConnectionError

# Original imports (preserved) - CORRECTED PATHS
from backend.app.db.connection import REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD
from backend.app.utils.logger import log_event, security_alert
from backend.app.security.security import validate_key_name, sanitize_redis_value
from backend.app.security.zkp_handler import validate_session_token
from backend.app.security.blockchain.blockchain_utils import log_redis_event
from tenacity import retry, stop_after_attempt, wait_exponential

# Security constants
MAX_REDIS_KEY_LENGTH = 256
AES_BLOCK_SIZE = 16
REDIS_HMAC_KEY = os.getenv("REDIS_HMAC_KEY", os.urandom(32).hex()).encode()
REDIS_CRYPTO_KEY = os.getenv("REDIS_CRYPTO_KEY", os.urandom(32).hex()).encode()
MAX_REDIS_LATENCY_MS = int(os.getenv("MAX_REDIS_LATENCY_MS", 150))

# Global kill switch
_redis_killed = False

class AESCipher:
    def __init__(self, key: bytes = REDIS_CRYPTO_KEY):
        self.key = key

    def encrypt(self, raw: Union[str, bytes]) -> bytes:
        if _redis_killed:
            return b''
        if isinstance(raw, str):
            raw = raw.encode()
        try:
            nonce = os.urandom(12)
            cipher = AESGCM(self.key)
            ciphertext = cipher.encrypt(nonce, raw, None)
            return nonce + ciphertext
        except Exception as e:
            security_alert(f"[SECURITY] Encryption failed: {str(e)[:50]}")
            return b''

    def decrypt(self, enc: bytes) -> str:
        if _redis_killed or not enc:
            return ""
        try:
            if len(enc) < 12:
                return ""
            nonce, ciphertext = enc[:12], enc[12:]
            cipher = AESGCM(self.key)
            decrypted = cipher.decrypt(nonce, ciphertext, None)
            return decrypted.decode()
        except Exception as e:
            security_alert(f"[SECURITY] Decryption failed: {str(e)[:50]}")
            return ""

_aes_cipher = AESCipher()

def _hmac_value(key: str, value: bytes) -> str:
    try:
        h = hmac.HMAC(REDIS_HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(f"{key}:{value}".encode())
        return h.finalize().hex()
    except Exception as e:
        security_alert(f"[SECURITY] HMAC generation failed: {str(e)[:50]}")
        return ""

class RedisManager:
    def __init__(self):
        self._client = None
        self._cipher = _aes_cipher
        # asyncio.run(self._connect())  # Comment out to avoid connection on import

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10), reraise=True)
    async def _connect(self):
        if _redis_killed:
            return
        try:
            self._client = AsyncRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, password=REDIS_PASSWORD, decode_responses=False, socket_timeout=MAX_REDIS_LATENCY_MS / 1000, ssl=True, ssl_cert_reqs='required')
            if not await self._client.ping():
                raise RedisConnectionError("Redis ping failed")
            log_event("🔒 Redis connected with TLS/SSL", level="SECURE")
        except Exception as e:
            security_alert(f"Redis connection failure: {str(e)}"); raise

    def _validate_key(self, key: str) -> bool:
        if _redis_killed or not validate_key_name(key) or len(key) > MAX_REDIS_KEY_LENGTH:
            security_alert(f"Invalid Redis key: {key}"); return False
        return True

    def _log_redis_event(self, key: str, action: str, user_id: Optional[str] = None):
        try:
            meta = {"key": key, "action": action, "timestamp": datetime.utcnow().isoformat()}
            if user_id: meta["user_id"] = user_id[:6] + "..."
            log_redis_event(meta)
        except Exception: pass

    async def set_key(self, key: str, value: Any, ttl: int = None, user_id: Optional[str] = None) -> bool:
        if not self._validate_key(key): return False
        try:
            start = time.perf_counter()
            sanitized = sanitize_redis_value(value)
            encrypted = self._cipher.encrypt(sanitized)
            h = _hmac_value(key, encrypted)
            
            await self._client.set(key, encrypted, ex=ttl)
            await self._client.set(f"hmac:{key}", h, ex=ttl + 30 if ttl else None)
            
            latency = (time.perf_counter() - start) * 1000
            if latency > MAX_REDIS_LATENCY_MS: security_alert(f"Redis latency attack: {latency}ms")
            
            self._log_redis_event(key, "set", user_id)
            return True
        except RedisError as e: security_alert(f"Redis set_key failure: {str(e)}"); return False

    async def get_key(self, key: str, user_id: Optional[str] = None) -> Optional[Any]:
        if not self._validate_key(key): return None
        try:
            start = time.perf_counter()
            encrypted = await self._client.get(key)
            stored_hmac = await self._client.get(f"hmac:{key}")
            
            if not encrypted or not stored_hmac: return None
            
            h = _hmac_value(key, encrypted)
            if not hmac.compare_digest(h.encode(), stored_hmac):
                security_alert(f"Redis HMAC mismatch: {key}"); return None
            
            decrypted = self._cipher.decrypt(encrypted)
            if not decrypted: return None
            
            latency = (time.perf_counter() - start) * 1000
            if latency > MAX_REDIS_LATENCY_MS: security_alert(f"Redis read latency attack: {latency}ms")
            
            self._log_redis_event(key, "get", user_id)
            try: return json.loads(decrypted)
            except json.JSONDecodeError: return decrypted
        except RedisError as e: security_alert(f"Redis get_key failure: {str(e)}"); return None

    async def delete_key(self, key: str, user_id: Optional[str] = None) -> bool:
        if not self._validate_key(key): return False
        try:
            await self._client.delete(key)
            await self._client.delete(f"hmac:{key}")
            self._log_redis_event(key, "delete", user_id)
            return True
        except RedisError as e: security_alert(f"Redis delete_key failure: {str(e)}"); return False
    
    async def flush_user(self, user_id: str) -> int:
        if _redis_killed or not user_id.isalnum(): return 0
        try:
            pattern = f"*:{user_id}:*"
            keys = [key async for key in self._client.scan_iter(match=pattern, count=100)]
            count = 0
            for key in keys:
                key_str = key.decode()
                if self._validate_key(key_str):
                    await self.delete_key(key_str)
                    count += 1
            log_event(f"🧹 Flushed {count} keys for user: {user_id}", level="GDPR")
            return count
        except RedisError as e: security_alert(f"Redis flush_user failure: {str(e)}"); return 0

    async def get_all_user_data(self, user_id: str) -> Dict[str, Any]:
        if _redis_killed: return {}
        result = {}
        try:
            pattern = f"*:{user_id}:*"
            async for key in self._client.scan_iter(match=pattern, count=1000):
                key_str = key.decode()
                if self._validate_key(key_str): result[key_str] = await self.get_key(key_str)
        except RedisError as e: security_alert(f"Redis get_all_user_data failure: {str(e)}"); return {}
        return result

def kill_redis():
    global _redis_killed
    _redis_killed = True
    log_event("Redis: Engine killed.", level="critical")

redis_db = RedisManager()

async def increment_request_count(user_id: str) -> int:
    # Stub function
    return 0

async def get_request_count(user_id: str) -> int:
    # Stub function
    return 0
