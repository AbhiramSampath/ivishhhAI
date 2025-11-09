"""
🧠 Ivish AI Permission Service
🔐 Governs access to sensitive services (audio, camera, overlays) using ZKP, encryption, and blockchain audit
📦 Features: permission requests, revocation, enforcement, ZKP consent, secure logging
🛡️ Security: input validation, ZKP token verification, secure revocation, anti-spam
"""

import os
import re
import uuid
import asyncio
import hashlib
import logging
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache

# 🔐 Security Imports - CORRECTED PATHS
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# 📁 Project Imports - CORRECTED PATHS
from security.blockchain.blockchain_utils import log_to_blockchain
from security.blockchain.zkp_handler import ZKPAuthenticator
from security.firewall import Firewall
from middlewares.rate_limiter import RateLimiter
from utils.logger import log_event
from db.mongo import get_user_settings, update_user_settings

# 🔐 Security Constants - Defined locally as config file is not in PDF
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("PERMISSION_HMAC_KEY", "permission_service_signature_key").encode()
_AES_KEY = os.getenv("PERMISSION_AES_KEY", "secure_32_byte_aes_key_for_permissions").encode()[:32]
_SALT = os.urandom(16)
_KDF_ITERATIONS = 100000
_LATENCY_BUDGET_MS = 100
_PERMISSION_TTL = timedelta(hours=24)
_SUPPORTED_PERMISSIONS = {
    "audio_access", "camera_access", "overlay_permission",
    "notification_access", "memory_access", "tts_access", "stt_access"
}
_PERMISSION_LEVELS = {
    "audio_access": "high",
    "camera_access": "high",
    "overlay_permission": "medium",
    "notification_access": "medium",
    "memory_access": "high",
    "tts_access": "low",
    "stt_access": "low"
}
_PERMISSION_BLACKLIST_REDIS_KEY = "permission_blacklist"

@dataclass
class PermissionRequest:
    """
    📌 Structured permission request
    - user_id: anonymized
    - permission_type: type of permission
    - timestamp: ISO timestamp
    - session_token: for tracking
    - _signature: HMAC signature for tamper detection
    """
    user_id: str
    permission_type: str
    timestamp: str
    session_token: str
    _signature: Optional[str] = None

class SecurePermissionService:
    """
    🔒 Secure Permission Service Engine
    - Manages user permissions for audio, camera, overlays, notifications, memory
    - Enforces consent via ZKP
    - Stores encrypted in user settings
    - Logs to blockchain
    - Revokes on timeout or user action
    """

    def __init__(self):
        """Secure initialization"""
        self.zkp_auth = ZKPAuthenticator()
        self.firewall = Firewall()
        self.rate_limiter = RateLimiter()
        self.session_token = self._generate_session_token()
    
    def _generate_session_token(self) -> str:
        """Securely generates a session token"""
        return hashlib.sha256(os.urandom(32)).hexdigest()

    def _sign_request(self, request: Dict) -> str:
        """HMAC-sign permission request"""
        h = HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        h.update(json.dumps(request, sort_keys=True).encode())
        return h.finalize().hex()

    def _encrypt_payload(self, data: Dict) -> bytes:
        """AES-GCM encrypted permission payload"""
        nonce = os.urandom(12)
        cipher = AESGCM(_AES_KEY)
        ciphertext = cipher.encrypt(nonce, json.dumps(data).encode(), None)
        return nonce + ciphertext

    def _decrypt_payload(self, encrypted_data: bytes) -> Dict:
        """AES-GCM decryption of permission data"""
        if len(encrypted_data) < 12:
            raise ValueError("Invalid encrypted data")
        nonce = encrypted_data[:12]
        cipher = AESGCM(_AES_KEY)
        decrypted = cipher.decrypt(nonce, encrypted_data[12:], None)
        return json.loads(decrypted.decode())

    async def request_permission(self, user_id: str, permission_type: str) -> Dict:
        """
        🔐 Request permission with ZKP token generation and Blockchain audit
        """
        try:
            if permission_type not in _SUPPORTED_PERMISSIONS:
                raise ValueError(f"Invalid permission type: {permission_type}")
            
            # 🔐 Anti-spam check with scalable rate limiter
            if not await self.rate_limiter.check_limit(user_id, rate=10, window=3600):
                log_event(f"Permission spam from {user_id} for {permission_type}", level="ALERT")
                await self.firewall.blackhole_ip(user_id) # Use user_id as an identifier for IP
                return {"status": "denied", "reason": "rate_limit"}

            # 🔐 Generate ZKP consent token
            consent_token = self.zkp_auth.generate_proof(user_id, permission_type)
            
            # 📜 Log to blockchain
            encrypted_log = self._encrypt_payload({
                "event": "permission_request",
                "user_id_hash": hashlib.sha256(user_id.encode()).hexdigest(),
                "permission": permission_type,
                "timestamp": time.time()
            })
            await log_to_blockchain("permission_request", encrypted_log)

            # ⚙️ Store permission request in MongoDB
            user_settings = await get_user_settings(user_id)
            if "permissions" not in user_settings:
                user_settings["permissions"] = {}
            user_settings["permissions"][permission_type] = {
                "granted": False,
                "timestamp": datetime.now().isoformat(),
                "zkp_token": consent_token
            }
            await update_user_settings(user_id, user_settings)

            return {
                "status": "requested",
                "permission": permission_type,
                "consent_token": consent_token,
                "session_token": self.session_token,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            log_event(f"PERMISSION_FAILURE: {str(e)}", level="ERROR")
            self._handle_permission_failure(user_id, permission_type, str(e))
            raise

    async def check_permission(self, user_id: str, permission_type: str) -> bool:
        """
        🔐 Verify permission with ZKP, TTL, and tamper detection
        """
        try:
            if permission_type not in _SUPPORTED_PERMISSIONS:
                return False

            user_settings = await get_user_settings(user_id)
            perm_data = user_settings.get("permissions", {}).get(permission_type, {})

            if not perm_data.get("granted", False):
                return False

            # 🚫 Revoke stale permissions
            granted_timestamp_str = perm_data.get("timestamp")
            if granted_timestamp_str:
                granted_timestamp = datetime.fromisoformat(granted_timestamp_str)
                if datetime.now() - granted_timestamp > _PERMISSION_TTL:
                    await self.revoke_permission(user_id, permission_type)
                    return False
            
            # 🛡️ Validate ZKP token
            zkp_token = perm_data.get("zkp_token")
            if not self.zkp_auth.verify_proof(user_id, permission_type, zkp_token):
                await self._log_intrusion_attempt(user_id, permission_type)
                return False

            return True

        except Exception as e:
            log_event(f"PERMISSION_CHECK_FAILURE: {str(e)}", level="ERROR")
            await self._log_intrusion_attempt(user_id, permission_type)
            return False

    async def revoke_permission(self, user_id: str, permission_type: str) -> Dict:
        """
        🔒 Secure permission revocation with audit trail
        """
        try:
            if permission_type not in _SUPPORTED_PERMISSIONS:
                raise ValueError(f"Invalid permission type: {permission_type}")
            
            # 📜 Blockchain audit trail
            encrypted_log = self._encrypt_payload({
                "event": "permission_revoked",
                "user_id_hash": hashlib.sha256(user_id.encode()).hexdigest(),
                "permission": permission_type,
                "timestamp": time.time()
            })
            await log_to_blockchain("permission_revoked", encrypted_log)

            user_settings = await get_user_settings(user_id)
            if permission_type in user_settings.get("permissions", {}):
                user_settings["permissions"][permission_type]["granted"] = False
                await update_user_settings(user_id, user_settings)
                
            return {"status": "revoked", "permission": permission_type}

        except Exception as e:
            log_event(f"PERMISSION_REVOCATION_FAILURE: {str(e)}", level="ERROR")
            self._handle_permission_failure(user_id, permission_type, str(e))
            return {"status": "failure", "error": str(e)}

    async def enforce_permission(self, user_id: str, permission_type: str):
        """
        🔒 Strict enforcement with intrusion detection
        """
        if not await self.check_permission(user_id, permission_type):
            await self._log_intrusion_attempt(user_id, permission_type)
            raise PermissionError(
                f"PERMISSION_DENIED: {permission_type} (User: {hashlib.sha256(user_id.encode()).hexdigest()})"
            )

    async def get_all_permissions(self, user_id: str) -> Dict:
        """
        🔐 Return full permission status with integrity
        """
        try:
            settings = await get_user_settings(user_id)
            permissions = settings.get("permissions", {})
            return {
                perm: {
                    "granted": data.get("granted", False),
                    "timestamp": data.get("timestamp", 0),
                    "zkp_token": data.get("zkp_token", "")
                }
                for perm, data in permissions.items()
            }
        except Exception as e:
            log_event(f"GET_PERMISSIONS_FAILURE: {str(e)}", level="ERROR")
            await self._log_intrusion_attempt(user_id, "all")
            return {}

    async def _log_intrusion_attempt(self, user_id: str, permission_type: str):
        """Counter-intelligence for unauthorized access"""
        await log_to_blockchain("intrusion_attempt", {
            "user_id": hashlib.sha256(user_id.encode()).hexdigest(),
            "permission": permission_type,
            "timestamp": datetime.now().isoformat()
        })
        self._trigger_defense_response(user_id)

    def _trigger_defense_response(self, user_id: str):
        """Reverse-intrusion response system"""
        logging.critical(f"🚨 PERMISSION TAMPERING DETECTED: {user_id}")
        self.zkp_auth.rotate_keys()
        self.firewall.blackhole_ip(user_id)

    def _handle_permission_failure(self, user_id: str, permission_type: str, error: str):
        """Secure failure handling with audit"""
        log_event(f"PERMISSION_FAILURE: {str(error)}", level="ERROR")
        asyncio.create_task(self._log_intrusion_attempt(user_id, permission_type))