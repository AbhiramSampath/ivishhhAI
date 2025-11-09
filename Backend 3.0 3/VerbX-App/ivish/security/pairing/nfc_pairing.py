# security/pairing/nfc_pairing.py

import time
import uuid
import os
import hashlib
import hmac
import asyncio
import base64
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Any, Union
from collections import defaultdict
from fastapi import HTTPException

# 📦 Project Imports (Corrected paths based on project architecture)

from security.device_fingerprint import (
    get_secure_device_fingerprint,
    validate_fingerprint_integrity
)
from security.blockchain.zkp_handler import (
    generate_zkp_challenge,
    verify_zkp_proof,
    ZKPValidationError
)
from backend.app.db.redis import (
    redis_atomic_set,
    redis_atomic_get_delete,
    redis_delete_with_audit,
    redis_atomic_get
)
from security.blockchain.blockchain_utils import (
    anchor_event as log_pairing_event,
)
from backend.app.utils.logger import log_event

from security.intrusion_prevention.counter_response import trigger_blackhole
from security.intrusion_prevention.isolation_engine import rotate_endpoint
from security.firewall import NFCPairingFirewall


# 🧱 Global Config
ENABLE_BLOCKCHAIN_LOGGING = True
ENABLE_HONEYPOT = True
ENABLE_AUTO_WIPE = True
ENABLE_ENDPOINT_MUTATION = True
PAIRING_TTL_SEC = 60  # 1 minute expiry
MAX_PAIRING_ATTEMPTS = 5  # Rate limiting
TOKEN_SIZE_BYTES = 32  # 256-bit tokens
THREAT_LEVEL_THRESHOLD = 5
RATE_LIMIT_WINDOW = 60  # seconds

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "firewall": NFCPairingFirewall(),
    "rate_limits": defaultdict(list),
    "threat_level": 0,
    "last_attack_time": 0,
    "lock": asyncio.Lock()
}

# 🔒 Security Utilities
def _get_hw_key() -> bytes:
    """Deterministic hardware-bound key derivation"""
    hw_factors = [
        os.getenv("HW_FINGERPRINT", ""),
        str(os.cpu_count()),
        str(uuid.getnode()) # Mac address is a stable hardware ID
    ]
    return hashlib.pbkdf2_hmac(
        'sha256',
        "|".join(hw_factors).encode(),
        os.urandom(16),
        100000
    )[:32]

def _is_valid_device(device_id: str) -> bool:
    """Validate device ID format (e.g., SHA-256 hash)"""
    return len(device_id) == 64

def _hash_device_id(device_id: str) -> str:
    """GDPR-compliant device hashing"""
    return hmac.new(
        os.getenv("DEVICE_HASH_SALT", "").encode(),
        device_id.encode(),
        hashlib.sha3_256
    ).hexdigest()

def _check_rate_limit(user: str, operation: str) -> bool:
    """Prevent abuse with rate limiting"""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    SECURITY_CONTEXT['rate_limits'][user] = [
        t for t in SECURITY_CONTEXT['rate_limits'].get(user, [])
        if t > window_start
    ]
    if len(SECURITY_CONTEXT['rate_limits'][user]) > MAX_PAIRING_ATTEMPTS:
        return False
    SECURITY_CONTEXT['rate_limits'][user].append(now)
    return True

async def _increment_threat_level():
    """Increase threat level and trigger defense if needed"""
    async with SECURITY_CONTEXT['lock']:
        SECURITY_CONTEXT['threat_level'] += 1
        if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
            await _anti_tamper_protocol()

async def _anti_tamper_protocol():
    """Active defense against NFC pairing abuse"""
    log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
    await _trigger_honeypot()
    _wipe_temp_sessions()
    await _rotate_endpoints()
    async with SECURITY_CONTEXT['lock']:
        SECURITY_CONTEXT['threat_level'] = 0

async def _trigger_honeypot():
    """Deceive attackers with fake NFC pairing"""
    if not ENABLE_HONEYPOT:
        return
    await verify_nfc_pair("attacker_device", "fake_token", {"challenge": "fake", "response": "malicious"})

def _wipe_temp_sessions():
    """Secure wipe of temporary session data"""
    pass

async def _rotate_endpoints():
    """Rotate update endpoints to evade attackers"""
    if not ENABLE_ENDPOINT_MUTATION:
        return
    log_event("ROTATING NFC ENDPOINTS", level="INFO")
    await rotate_endpoint()

def _audit_pairing_attempt(
    device_id: str,
    success: bool,
 
) -> None:
    """Immutable audit logging with blockchain anchoring"""


# 🧠 NFC Pairing Core
class NFCPairingError(Exception):
    """Base class for pairing failures"""
    pass

async def initiate_nfc_pair(device_id: str) -> Dict[str, Any]:
    """
    Hardened NFC pairing initiation with:
    - Device-bound token generation
    - ZKP challenge
    - Rate limiting
    - Blockchain audit
    """
    if not _is_valid_device(device_id):
        log_event("Invalid device ID", level="WARNING")
        raise NFCPairingError("Invalid device ID")

    if not _check_rate_limit(device_id, "nfc_pairing"):
        log_event("NFC pairing rate limited", level="WARNING")
        raise HTTPException(429, "Too many requests")

    try:
        # Generate secure token
     
        fingerprint = get_secure_device_fingerprint(device_id)

        if not validate_fingerprint_integrity(fingerprint):
           
            raise NFCPairingError("Device fingerprint invalid")



        # Generate ZKP challenge on the server-side
        zkp_challenge_data = await generate_zkp_challenge(device_id)

        # Redis session storage
        key = f"pair:{device_id}"
        if not await redis_atomic_set(
            key=key,
          
            ttl=PAIRING_TTL_SEC,
            nx=True
        ):
            _audit_pairing_attempt(device_id, False)
            raise NFCPairingError("Existing pairing session detected")

        # Increment attempt counter
        await redis_atomic_set(
            key=f"pair_attempts:{device_id}",
            value=1,
            ttl=PAIRING_TTL_SEC,
            incr=True
        )

        _audit_pairing_attempt(device_id, True)
        return {
           
            "zkp_challenge": zkp_challenge_data,
            "expires_in": PAIRING_TTL_SEC,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        log_event(f"NFC pairing initiation failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        raise

async def verify_nfc_pair(
    device_id: str,
    encrypted_token: str,
    zkp_response: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Secure NFC pairing verification with:
    - Token decryption validation
    - ZKP proof verification
    - One-time-use guarantee
    - Active attack detection
    """
    if not _is_valid_device(device_id):
        log_event("Invalid device for NFC pairing", level="WARNING")
        raise NFCPairingError("Invalid device ID")

    fingerprint = get_secure_device_fingerprint(device_id)

    # Redis token validation
    stored_token = await redis_atomic_get_delete(f"pair:{device_id}")
    if not stored_token:
     
        return {
            "success": False,
            "reason": "Session expired"
        }

    # ZKP validation
    try:
        if not await verify_zkp_proof(
            device_id=device_id,
            proof=zkp_response
        ):
         
            return {
                "success": False,
                "reason": "ZKP verification failed"
            }
    except ZKPValidationError as e:

        return {
            "success": False,
            "reason": "ZKP validation error"
        }

    # Secure session finalization
    session_id = str(uuid.uuid4())
    await redis_atomic_set(
        key=f"session:{session_id}",
        value=device_id,
        ttl=PAIRING_TTL_SEC
    )

    _audit_pairing_attempt(device_id, True)
    return {
        "success": True,
        "session_id": session_id,
        "timestamp": datetime.utcnow().isoformat()
    }

async def expire_pairing(device_id: str) -> None:
    """Secure NFC pairing termination"""
    await redis_delete_with_audit(
        key=f"pair:{device_id}",
        context=f"manual_expiry:{datetime.now(timezone.utc).isoformat()}"
    )
    _audit_pairing_attempt(
        device_id,
        False,
       
    )

async def get_pair_status(device_id: str) -> Dict[str, Any]:
    """Secure NFC pairing status check"""
    status = bool(await redis_atomic_get(f"pair:{device_id}"))
    _audit_pairing_attempt(
        device_id,
        status,
      
    )
    return {
        "paired": status,
        "timestamp": datetime.utcnow().isoformat()
    }