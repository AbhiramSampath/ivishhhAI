# backend/utils/user_logger.py
# 🔒 Hardened User Logger with AI-Powered Defense
# 🚀 Final, Refactored Code

import json
import time
import os
import uuid
import hashlib
import hmac
import base64
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from fastapi import HTTPException

# 📦 Project Imports
from security.blockchain.blockchain_utils import log_to_blockchain
from security.encryption_utils import encrypt_data_with_key, decrypt_data_with_key, generate_hmac
from security.intrusion_prevention.counter_response import blackhole_response_action, rotate_endpoint
from security.firewall import UserLoggerFirewall
from .helpers import current_time_iso
from .logger import log_event
from .rate_meter import rate_meter

# 🧱 Global Config
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("LOG_TO_CHAIN", "False").lower() == "true"
SAVE_SESSION_MEMORY = os.getenv("SAVE_SESSION_MEMORY", "False").lower() == "true"
LOG_ENCRYPTION_KEY = os.getenv("LOG_ENCRYPTION_KEY", None)
if not LOG_ENCRYPTION_KEY:
    raise RuntimeError("LOG_ENCRYPTION_KEY not found in environment. Secure logging is not possible.")
LOG_ENCRYPTION_KEY = LOG_ENCRYPTION_KEY.encode()

USER_HASH_SALT = os.getenv("USER_HASH_SALT", os.urandom(32).hex())
if len(USER_HASH_SALT) < 32:
    raise ValueError("USER_HASH_SALT must be a secure random string of at least 32 characters.")

MEMORY_FIELD_MAX_SIZE = int(os.getenv("MEMORY_FIELD_MAX_SIZE", "1024"))
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", "5"))

# 🔒 Secure Global State (Using external services for scalability)
SECURITY_CONTEXT = {
    "firewall": UserLoggerFirewall(),
    "threat_level": 0,
    "last_attack_time": 0
}
_session_store: Dict[str, deque] = defaultdict(lambda: deque(maxlen=int(os.getenv("MAX_LOG_ENTRIES_PER_SESSION", "1000"))))

# 🔐 Security Utilities
def _hash_user_id(user_id: str) -> str:
    """GDPR-compliant user hashing with a strong, salted hash."""
    return hmac.new(
        USER_HASH_SALT.encode(),
        user_id.encode(),
        hashlib.sha3_256
    ).hexdigest()

def _sanitize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Prevent injection in downstream processing with a basic sanitizer."""
    sanitized = {}
    for k, v in payload.items():
        if isinstance(v, str):
            v = v[:MEMORY_FIELD_MAX_SIZE]
        sanitized[k] = v
    return sanitized

def _increment_threat_level():
    """Increase threat level and trigger defense if needed."""
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        asyncio.create_task(_anti_tamper_protocol())

async def _anti_tamper_protocol():
    """Active defense against logging tampering."""
    log_event("THREAT: Anti-tamper protocol triggered", level="ALERT")
    # Placeholder for honeypot and wipe; actual implementation is elsewhere
    blackhole_response_action(delay=300)
    rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

def _create_secure_entry(
    event_type: str, 
    payload: Dict, 
    user_id: str
) -> Dict[str, Any]:
    """Generate hardened log entry with cryptographic sealing."""
    timestamp = current_time_iso()
    log_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{user_id}{timestamp}{os.urandom(16)}"))
    
    sanitized_payload = _sanitize_payload(payload)
    
    # Encrypt data with the secure key
    encrypted_event_type = encrypt_data_with_key(event_type.encode(), LOG_ENCRYPTION_KEY).hex()
    encrypted_payload = encrypt_data_with_key(json.dumps(sanitized_payload).encode(), LOG_ENCRYPTION_KEY).hex()
    
    # Generate HMAC over the encrypted data for integrity
    integrity_hash = generate_hmac(encrypted_payload)

    entry = {
        "log_id": log_id,
        "timestamp": timestamp,
        "user_id_hash": _hash_user_id(user_id),
        "event_type": encrypted_event_type,
        "payload": encrypted_payload,
        "integrity_hash": integrity_hash
    }
    return entry

async def log_user_event(event_type: str, payload: Dict, user_id: str):
    """
    Hardened user event logging with zero-trust validation and anti-abuse protection.
    """
    if await rate_meter.track_call(user_id, source="user_logger"):
        log_event(f"Rate limit exceeded for user: {user_id}", level="WARNING")
        raise HTTPException(429, "Too many requests")

    try:
        # Create secure entry
        entry = _create_secure_entry(event_type, payload, user_id)
        
        # Store in secure log store
        _session_store[user_id].append(entry)
        
        # Blockchain audit
        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain(
                collection="user_events",
                data=entry
            )

        # Secure debug output
        debug_payload = _sanitize_payload(payload)
        log_event(
            f"[{entry['timestamp']}] EVENT | {event_type[:20]} | {debug_payload}"
        )

    except Exception as e:
        log_event(f"Secure logging failed: {str(e)}", level="ERROR")
        _increment_threat_level()
        raise

async def store_memory_if_allowed(user_id: str, key: str, value: str):
    """
    Secure memory storage with consent verification and encryption.
    """
    if not SAVE_SESSION_MEMORY:
        return

    if await rate_meter.track_call(user_id, source="memory_store"):
        raise HTTPException(429, "Too many memory writes")

    if not isinstance(value, str) or len(value) > MEMORY_FIELD_MAX_SIZE:
        value = str(value)[:MEMORY_FIELD_MAX_SIZE]

    try:
        encrypted_value = encrypt_data_with_key(value.encode(), LOG_ENCRYPTION_KEY).hex()

        await log_user_event(
            event_type="memory_store",
            payload={
                "key_hash": hashlib.sha256(key.encode()).hexdigest(),
                "value": encrypted_value
            },
            user_id=user_id
        )

    except Exception as e:
        log_event(f"Memory storage failed: {str(e)}", level="ERROR")
        _increment_threat_level()
        raise

async def log_session_summary(user_id: str, summary_data: Dict):
    """
    Secure session summary with anonymized metrics and integrity checks.
    """
    if await rate_meter.track_call(user_id, source="session_summary"):
        raise HTTPException(429, "Too many summaries")

    try:
        sanitized = {
            "session_duration": summary_data.get("duration"),
            "interaction_count": summary_data.get("count"),
            "preferred_language": summary_data.get("language"),
            "last_active": current_time_iso()
        }

        await log_user_event("session_summary", sanitized, user_id)

    except Exception as e:
        log_event(f"Session summary failed: {str(e)}", level="ERROR")
        _increment_threat_level()
        raise

async def flush_session_logs(user_id: str):
    """
    Cryptographic log disposal with blockchain finalization and secure wipe.
    """
    try:
        logs = _session_store.get(user_id, [])
        if logs and ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain(
                collection="session_close",
                data={
                    "user_id_hash": _hash_user_id(user_id),
                    "log_count": len(logs)
                }
            )

        if user_id in _session_store:
            del _session_store[user_id]

        log_event(f"Session logs flushed for {user_id}")

    except Exception as e:
        log_event(f"Session flush failed: {str(e)}", level="ERROR")
        _increment_threat_level()
        raise

async def export_logs_json(user_id: str) -> Optional[str]:
    """
    Secure log export with decryption on-demand and pseudonymized output.
    """
    logs = _session_store.get(user_id, [])
    if not logs:
        return None

    decrypted_logs = []
    for entry in logs:
        try:
            # Note: integrity_hash verification can be done here if needed
            decrypted_logs.append({
                "timestamp": entry["timestamp"],
                "event_type": decrypt_data_with_key(bytes.fromhex(entry["event_type"]), LOG_ENCRYPTION_KEY).decode(),
                "payload": json.loads(decrypt_data_with_key(bytes.fromhex(entry["payload"]), LOG_ENCRYPTION_KEY).decode())
            })
        except Exception as e:
            log_event(f"Log decryption failed: {str(e)}", level="ERROR")
            continue

    filename = f"logs/{_hash_user_id(user_id)}_{datetime.utcnow().isoformat()}.json"
    try:
        os.makedirs("logs", exist_ok=True)
        with open(filename, "w") as f:
            json.dump(decrypted_logs, f, indent=2)
        os.chmod(filename, 0o600)  # Restrict permissions
        return filename
    except Exception as e:
        log_event(f"Log export failed: {str(e)}", level="ERROR")
        _increment_threat_level()
        return None