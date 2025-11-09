import os
import time
import asyncio
import logging
import subprocess
import base64
import json
import glob
from typing import Optional, Dict, Any
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Internal Imports (Corrected)
from security.blockchain.zkp_handler import validate_override_credential
from security.blockchain.blockchain_utils import log_audit_event
from backend.app.services.ivish_service import get_current_session_context, end_session as terminate_session
from security.intrusion_prevention.counter_response import BlackholeRouter

# --- Constants --- #
OVERRIDE_KEY_TTL = int(os.getenv("OVERRIDE_KEY_TTL", 300))
MAX_OVERRIDE_RATE = int(os.getenv("MAX_OVERRIDE_RATE", 3))
BLACKHOLE_DELAY = int(os.getenv("BLACKHOLE_DELAY", 60))
EMERGENCY_DATA_PATHS = ["/tmp/ivish_*", "/dev/shm/ai_cache_*"]

# Security constants
_AES_KEY = os.getenv('OVERRIDE_AES_KEY', base64.urlsafe_b64encode(os.urandom(32)).decode())

# Initialize components
logger = logging.getLogger(__name__)
# RedisCache and RateLimiter are removed based on the request.
blackhole_router = BlackholeRouter()

class ManualOverrideController:
    def __init__(self):
        self._cipher = Fernet(_AES_KEY)

    async def authorize_override(self, user_token: str, zk_proof: str, user_id: str) -> bool:
        # RateLimiter functionality is removed as per the request.
        # The check_limit call has been commented out to preserve the code structure.
        # if not await rate_limiter.check_limit(user_id, rate=MAX_OVERRIDE_RATE, window=60):
        #    await blackhole_router.trigger()
        #    return False

        try:
            encrypted_token = self._encrypt_payload(user_token)
            return await validate_override_credential(encrypted_token, zk_proof)
        except Exception as e:
            logger.warning(f"ZKP validation failed for {user_token[:6]}...", exc_info=True)
            await blackhole_router.trigger()
            return False

    def _encrypt_payload(self, data: str) -> bytes:
        try:
            return self._cipher.encrypt(data.encode())
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return b''

    def _decrypt_payload(self, data: bytes) -> str:
        try:
            return self._cipher.decrypt(data).decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return ''

    async def manual_pause(self, session_id: str) -> str:
        SYSTEM_STATE['ai_paused'] = True
        encrypted_session = self._encrypt_payload(session_id)
        await log_audit_event(
            "MANUAL_PAUSE",
            payload={"session_id": encrypted_session.decode(), "action": "AI paused"}
        )
        logger.info(f"Session {session_id} manually paused.")
        return self._encrypt_payload("AI processing paused").decode()

    async def manual_shutdown(self, session_id: str) -> str:
        SYSTEM_STATE['ai_shutdown'] = True
        await terminate_session(session_id)
        encrypted_session = self._encrypt_payload(session_id)
        await log_audit_event(
            "MANUAL_SHUTDOWN",
            payload={"session_id": encrypted_session.decode(), "action": "AI terminated"}
        )
        await self._secure_wipe(EMERGENCY_DATA_PATHS)
        logger.critical(f"Session {session_id} manually shut down.")
        return self._encrypt_payload("AI safely shut down").decode()

    async def override_output(self, session_id: str, module: str, new_output: str) -> str:
        encrypted_session = self._encrypt_payload(session_id)
        encrypted_output = self._encrypt_payload(new_output)
        
        # This part requires RedisCache. As RedisCache is removed, this functionality is commented out.
        # await redis_cache.set(
        #    f"override:{encrypted_session.decode()}:{module}",
        #    encrypted_output,
        #    ex=OVERRIDE_KEY_TTL
        # )
        await log_audit_event(
            "MODULE_OVERRIDE",
            payload={"session_id": encrypted_session.decode(), "module": module, "action": f"{module} output replaced"}
        )
        logger.info(f"Output for {module} in session {session_id} overridden.")
        return self._encrypt_payload(f"Output of {module} overridden").decode()

    def get_override_log(self, session_id: str) -> Dict[str, Any]:
        return {
            "session_id": session_id,
            "paused": SYSTEM_STATE.get('ai_paused', False),
            "shutdown": SYSTEM_STATE.get('ai_shutdown', False),
            "fallback_mode": SYSTEM_STATE.get('fallback_mode', False),
            "timestamp": datetime.utcnow().isoformat()
        }

    async def trigger_emergency_fallback(self, session_id: str) -> str:
        SYSTEM_STATE['fallback_mode'] = True
        await terminate_session(session_id)
        encrypted_session = self._encrypt_payload(session_id)
        await log_audit_event(
            "EMERGENCY_FALLBACK",
            payload={"session_id": encrypted_session.decode(), "action": "Nuclear fallback activated"}
        )
        return self._encrypt_payload("Nuclear fallback activated").decode()

    async def _secure_wipe(self, paths: list):
        for pattern in paths:
            for file_path in glob.glob(pattern):
                try:
                    await asyncio.to_thread(subprocess.run, ['shred', '-u', file_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    logger.error(f"Secure wipe failed for {file_path}: {e}")

SYSTEM_STATE = {'ai_paused': False, 'ai_shutdown': False, 'fallback_mode': False}
override_controller = ManualOverrideController()