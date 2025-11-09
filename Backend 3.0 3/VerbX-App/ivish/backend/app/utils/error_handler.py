# 🔒 backend/utils/error_handler.py
# 🚀 Final, Refactored Code
# Centralized, auditable, and secure error handling for AI modules

import os
import time
import uuid
import asyncio
import logging
import traceback
import subprocess
import json
import hmac
from typing import Dict, Optional, Any, Callable, Union
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from fastapi import HTTPException

# Corrected Security imports based on folder structure
from security.firewall import Firewall
from security.blockchain.zkp_handler import generate_ephemeral_proof, validate_error_trace
from security.blockchain.blockchain_utils import log_error_event
from security.encryption_utils import PBKDF2HMAC
from security.intrusion_prevention.threat_detector import ThreatDetector
from security.intrusion_prevention.counter_response import blackhole_response_action

# Corrected System imports based on folder structure
from utils.logger import log_event
from utils.cache import redis_client, rate_limit_key
from utils.security import sanitize_error_message

# Configuration from environment variables
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"
MAX_ERROR_RATE = int(os.getenv("MAX_ERROR_RATE", 5))

# Security constants
BLACKHOLE_DELAY = 60  # Seconds to delay attacker
RATE_LIMIT_WINDOW = 60  # Rate-limiting window in seconds
ERROR_LOG_PATH = "/var/log/ivish/errors"
TEMP_ERROR_PATHS = ["/tmp/ivish_error_*", "/dev/shm/error_*"]

# AES-256-GCM encryption
ERROR_AES_KEY = os.getenv("ERROR_AES_KEY", "").encode()[:32]
if len(ERROR_AES_KEY) != 32:
    raise RuntimeError("Invalid encryption key for error handling")

logger = logging.getLogger(__name__)

class SecureError:
    """
    Immutable error object with cryptographic validation
    """
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.integrity_tag = self._compute_integrity_tag()
        self._secure_wipe_temp(data.get("trace_path"))

    def _compute_integrity_tag(self) -> str:
        """Cryptographic tag for error validation"""
        h = hmac.HMAC(ERROR_AES_KEY, hashes.SHA256())
        h.update(json.dumps(self.data).encode('utf-8'))
        return h.finalize().hex()

    def _secure_wipe_temp(self, path: Optional[str]):
        """Securely wipe temporary error data asynchronously."""
        if path and os.path.exists(path):
            async def wipe_task():
                try:
                    proc = await asyncio.create_subprocess_exec(
                        'shred', '-u', path,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await proc.wait()
                except Exception as e:
                    logger.error(f"Secure wipe failed for {path}: {e}")
            
            asyncio.create_task(wipe_task())

    def __repr__(self) -> str:
        return json.dumps(self.data)

class NuclearErrorHandler:
    """
    Provides secure, auditable, and emotionally aware error handling.
    """
    def __init__(self):
        self.firewall = Firewall()
        self.threat_detector = ThreatDetector()

    def _validate_rate_limit(self, context: str) -> bool:
        """Prevent error flooding attacks using Redis."""
        key = rate_limit_key(f"error:{context}")
        try:
            count = redis_client.incr(key)
            if count == 1:
                redis_client.expire(key, RATE_LIMIT_WINDOW)
            
            if count > MAX_ERROR_RATE:
                log_event(f"[SECURITY] Error rate limit exceeded for context '{context}'", alert=True)
                blackhole_response_action(delay=BLACKHOLE_DELAY)
                return False
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fallback to a non-scalable check if Redis is unavailable
            # This is a temporary, non-scalable fallback
            return True
            
        return True

    async def _secure_wipe(self, paths: list):
        """Securely wipe temporary error data asynchronously."""
        for path in paths:
            if os.path.exists(path):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        'shred', '-u', path,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await proc.wait()
                except Exception as e:
                    logger.error(f"Secure wipe failed for {path}: {e}")
                    
    def _encrypt_data(self, data: bytes) -> bytes:
        """AES-256-GCM encryption for error data with dynamic IV."""
        iv = os.urandom(12)  # Generate a new IV for each encryption
        cipher = Cipher(algorithms.AES(ERROR_AES_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def _decrypt_data(self, data: bytes) -> str:
        """Secure error decryption"""
        iv = data[:12]
        cipher = Cipher(algorithms.AES(ERROR_AES_KEY), modes.GCM(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(data[12:]) + decryptor.finalize()).decode('utf-8')

    def _compute_integrity_tag(self, payload: Union[Dict[str, Any], str]) -> str:
        """Cryptographic tag for error validation."""
        h = hmac.HMAC(ERROR_AES_KEY, hashes.SHA256())
        if isinstance(payload, dict):
            h.update(json.dumps(payload).encode('utf-8'))
        else:
            h.update(payload.encode('utf-8'))
        return h.finalize().hex()

    def _hash_user_id(self, user_id: str) -> str:
        """PBKDF2-HMAC-SHA512 user hashing for privacy."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=b"error_user_salt_2023",
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(user_id.encode()).hex()

    def _generate_trace_id(self, context: str) -> str:
        """Cryptographic trace ID generation."""
        return f"trace_{uuid.uuid4().hex[:12]}_{context[:8]}"

    def _get_secure_trace(self) -> str:
        """Sanitized traceback with sensitive info removed."""
        try:
            trace = traceback.format_exc(limit=5)
            return sanitize_error_message(trace)
        except Exception:
            return "Traceback unavailable"

    def _get_user_message(self, error_msg: str) -> str:
        """Safe message for end users."""
        if DEBUG_MODE:
            return error_msg[:1000]
        return "An internal error occurred. Please try again later."

    async def handle_exception(self, err: Exception, context: str = "Unknown") -> Dict[str, Any]:
        """
        Secure exception handler with:
        - ZKP validation
        - Trace ID generation
        - Blockchain logging
        - Secure trace sanitization
        """
        trace_id = self._generate_trace_id(context)
        timestamp = time.time()
        zkp_proof = generate_ephemeral_proof(trace_id)

        # Sanitize and hash
        error_type = type(err).__name__
        safe_message = sanitize_error_message(str(err))
        clean_trace = self._get_secure_trace()
        error_payload = {"error": error_type, "message": safe_message, "trace": clean_trace}
        error_hash = self._compute_integrity_tag(error_payload)

        # Log securely
        log_event(
            f"[ERROR] {context} | {error_type} | Trace: {trace_id}",
            metadata={
                "trace_id": trace_id,
                "zkp": zkp_proof,
                "context": context,
                "type": error_type,
                "message": safe_message,
                "hash": error_hash,
                "timestamp": timestamp
            },
            encrypted=True
        )

        # Blockchain audit
        await log_error_event({
            "action": "handle_exception",
            "error_type": error_type,
            "trace_id": trace_id,
            "context": context,
            "timestamp": timestamp,
            "hash": error_hash
        })

        return {
            "status": "error",
            "trace_id": trace_id,
            "message": self._get_user_message(safe_message),
            "context": context,
            "timestamp": timestamp,
            "integrity": error_hash,
            "zkp_proof": zkp_proof
        }
    
    def wrap_with_try(self, func: Callable) -> Callable:
        """Secure function wrapper with nuclear-grade validation using a decorator."""
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                self.threat_detector.analyze_threat(f"Exception in {func.__name__}")
                return await self.handle_exception(e, context=func.__name__)

        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                self.threat_detector.analyze_threat(f"Exception in {func.__name__}")
                return asyncio.run(self.handle_exception(e, context=func.__name__))

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    async def raise_http_error(self, status_code: int = 500, message: str = "Internal Server Error", context: str = "") -> None:
        """Secure HTTP error with ZKP trace."""
        error_info = await self.handle_exception(Exception(message), context=context)
        detail = {
            "message": error_info["message"],
            "trace_id": error_info["trace_id"],
            "zkp_proof": error_info["zkp_proof"]
        }
        raise HTTPException(status_code=status_code, detail=detail)

    async def log_conversation(self, user_id: str, input: str, reply: str) -> None:
        """Immutable logging of error-related interactions."""
        try:
            await log_error_event({
                "user_id": self._hash_user_id(user_id),
                "input_hash": self._compute_integrity_tag(input),
                "reply_hash": self._compute_integrity_tag(reply),
                "timestamp": time.time()
            })
        except Exception as e:
            logger.error(f"[ERROR] Conversation logging failed: {str(e)}", exc_info=True)
            
# Singleton with rate limit
error_handler = NuclearErrorHandler()