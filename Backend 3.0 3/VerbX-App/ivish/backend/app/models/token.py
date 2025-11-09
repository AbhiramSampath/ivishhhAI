import jwt
import uuid
import time
import os
import hmac
import hashlib
import logging
import traceback
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union, List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# 📦 Project Imports - CORRECTED PATHS
from utils.logger import log_event
from security.security import encrypt_data, decrypt_data
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import BlackholeRouter, rotate_endpoint
from security.firewall import Firewall as TokenFirewall
from security.blockchain.blockchain_utils import secure_audit_log
from middlewares.rate_limiter import RateLimiter

# 🧱 Global Config - Defined locally as config file is not in PDF
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "True").lower() == "true"
ENABLE_HONEYPOT = os.getenv("ENABLE_HONEYPOT", "True").lower() == "true"
ENABLE_ENDPOINT_MUTATION = os.getenv("ENABLE_ENDPOINT_MUTATION", "True").lower() == "true"
TOKEN_EXPIRY_MINUTES = int(os.getenv("TOKEN_EXPIRY_MINUTES", 15))
TOKEN_ROTATION_INTERVAL = timedelta(hours=1)
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", 5))
MIN_QUERY_TIME = float(os.getenv("MIN_QUERY_TIME", 0.1))
TOKEN_RATE_LIMIT = int(os.getenv("TOKEN_RATE_LIMIT", 100))

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "signing_keys": {
        "primary": os.urandom(32),
        "secondary": os.urandom(32)
    },
    "revocation_cache": {},
    "last_rotation": datetime.utcnow(),
    "firewall": TokenFirewall(),
    "threat_level": 0,
}

# 🔒 Initialize Security Context
def _derive_hw_key() -> bytes:
    hw_factors = [os.getenv("HW_FINGERPRINT", "")]
    return HKDF(algorithm=hashes.SHA512(), length=32, salt=os.urandom(16), info=b"token_encryption", backend=default_backend()).derive("|".join(hw_factors).encode())

def _rotate_keys_if_needed():
    now = datetime.utcnow()
    if (now - SECURITY_CONTEXT["last_rotation"]) > TOKEN_ROTATION_INTERVAL:
        SECURITY_CONTEXT["signing_keys"]["secondary"] = SECURITY_CONTEXT["signing_keys"]["primary"]
        SECURITY_CONTEXT["signing_keys"]["primary"] = _derive_hw_key()
        SECURITY_CONTEXT["last_rotation"] = now

def _get_signing_key() -> bytes:
    _rotate_keys_if_needed()
    return SECURITY_CONTEXT["signing_keys"]["primary"]

def _hash_user_id(user_id: str) -> str:
    salt = os.getenv("USER_HASH_SALT", "").encode()
    return hmac.new(salt, user_id.encode(), hashlib.sha3_512).hexdigest()

def _get_current_device_id() -> str:
    factors = [os.getenv("DEVICE_ID", "")]
    return hashlib.sha256("|".join(factors).encode()).hexdigest()

async def _is_revoked(jti: str) -> bool:
    now = time.time()
    if jti in SECURITY_CONTEXT["revocation_cache"]:
        return True
    try:
        from security.blockchain.blockchain_utils import is_token_revoked
        return await is_token_revoked(jti)
    except Exception:
        return False

async def _add_to_revocation_list(jti: str, reason: str) -> bool:
    try:
        SECURITY_CONTEXT["revocation_cache"][jti] = {"reason": reason, "timestamp": datetime.utcnow().isoformat()}
        return True
    except Exception as e:
        log_event(f"Revocation failed: {str(e)}", level="ERROR")
        return False

def _generate_nonce() -> str:
    return base64.b64encode(os.urandom(16)).decode()[:16]

async def _increment_threat_level():
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        await _anti_tamper_protocol()

async def _anti_tamper_protocol():
    log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
    if ENABLE_HONEYPOT: asyncio.create_task(_trigger_honeypot())
    await BlackholeRouter().trigger()
    if ENABLE_ENDPOINT_MUTATION: rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

async def _trigger_honeypot():
    await create_access_token({"user_id": "attacker", "device_id": "fake"}, zkp_proof="fake_zkp")

def _is_valid_token(token: str) -> bool:
    try:
        header, payload, signature = token.split(".")
        return len(header) > 16 and len(payload) > 32
    except Exception:
        return False

def _is_valid_jti(jti: str) -> bool:
    return len(jti) == 36

def _is_valid_device(device_id: str) -> bool:
    return len(device_id) == 64

async def create_access_token(
    data: Dict[str, Union[str, int]],
    expiry_minutes: int = TOKEN_EXPIRY_MINUTES,
    scopes: Optional[List[str]] = None,
    zkp_proof: Optional[str] = None
) -> str:
    if zkp_proof and not await _verify_zkp(zkp_proof, "token_issue", data.get("user_id")):
        log_event("Invalid token ZKP", level="WARNING"); await _increment_threat_level(); raise PermissionError("Invalid ZKP proof")
    if not data.get("user_id"): log_event("Token without user_id", level="WARNING"); await _increment_threat_level(); raise ValueError("Missing user_id in token")
    try:
        device_hash = _get_current_device_id()
        if not _is_valid_device(device_hash): raise RuntimeError("Device hash validation failed")
        payload = {"sub": str(data.get("user_id")), "iat": datetime.utcnow(), "exp": datetime.utcnow() + timedelta(minutes=expiry_minutes), "jti": str(uuid.uuid4()), "scopes": scopes or [], "session_id": encrypt_data(data.get("session_id")), "device_hash": device_hash, "iss": "ivish_secure_token_service", "aud": "ivish_core_services", "nonce": _generate_nonce(), "zkp_hash": _hash_zkp(zkp_proof) if zkp_proof else None}
        token = jwt.encode(payload, _get_signing_key(), algorithm="HS512")
        if ENABLE_BLOCKCHAIN_LOGGING:
            secure_audit_log(event="token_issued", payload={"user_id_hash": _hash_user_id(payload["sub"]), "jti": payload["jti"], "scope_hash": hashlib.sha3_256(",".join(payload["scopes"]).encode()).hexdigest(), "issued_at": payload["iat"].isoformat(), "device_hash": payload["device_hash"], "nonce": payload["nonce"]})
        return token
    except Exception as e:
        log_event(f"Token creation failed: {str(e)}", level="ERROR"); await _increment_threat_level(); raise

async def verify_token(token: str, required_scopes: Optional[List[str]] = None, require_device_match: bool = True) -> Dict[str, Any]:
    if not _is_valid_token(token): log_event("Invalid token format", level="WARNING"); await _increment_threat_level(); raise PermissionError("Invalid token")
    try:
        if await _is_revoked(jwt.decode(token, options={"verify_signature": False}).get("jti")): log_event("Token revoked", level="WARNING"); await _increment_threat_level(); raise PermissionError("Token revoked")
        if require_device_match:
            current_device_hash = _get_current_device_id()
            if jwt.decode(token, options={"verify_signature": False}).get("device_hash") != current_device_hash: log_event("Token device mismatch", level="ALERT"); await _increment_threat_level(); raise PermissionError("Device mismatch")
        decoded = jwt.decode(token, _get_signing_key(), algorithms=["HS512"], audience="ivish_core_services", issuer="ivish_secure_token_service")
        if required_scopes and not all(scope in decoded.get("scopes", []) for scope in required_scopes): log_event("Insufficient token scopes", level="WARNING"); await _increment_threat_level(); raise PermissionError("Insufficient scopes")
        if datetime.utcnow().timestamp() > decoded["exp"]: raise jwt.ExpiredSignatureError("Token expired")
        return decoded
    except jwt.ExpiredSignatureError: log_event("Token expired", level="WARNING"); raise
    except jwt.InvalidTokenError as e: log_event(f"Invalid token: {str(e)}", level="WARNING"); await _increment_threat_level(); raise PermissionError("Invalid token")

def revoke_token(jti: str, revocation_reason: str) -> bool:
    if not _is_valid_jti(jti): log_event("Invalid JTI in revocation", level="WARNING"); _increment_threat_level(); return False
    try:
        if ENABLE_BLOCKCHAIN_LOGGING: secure_audit_log(event="token_revoked", payload={"jti": jti, "reason": revocation_reason, "timestamp": datetime.utcnow().isoformat()})
        revoked = _add_to_revocation_list(jti, revocation_reason)
        return revoked
    except Exception as e: log_event(f"Token revocation failed: {str(e)}", level="ERROR"); _increment_threat_level(); return False

def is_expired(token: str) -> bool:
    try: decoded = jwt.decode(token, options={"verify_signature": False}); return datetime.utcnow().timestamp() > decoded["exp"]
    except Exception: return True

def parse_token(token: str) -> Dict[str, Any]:
    try: return jwt.decode(token, options={"verify_signature": False})
    except Exception as e: log_event(f"Token parse failed: {str(e)}", level="ERROR"); return {}

def get_token_metadata(token: str) -> Dict[str, Any]:
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return {"user_id": decoded.get("sub"), "session_id": decrypt_data(decoded.get("session_id")), "issued_at": decoded.get("iat"), "expires_at": decoded.get("exp"), "scopes": decoded.get("scopes", []), "device_hash": decoded.get("device_hash"), "nonce": decoded.get("nonce"), "jti": decoded.get("jti")}
    except Exception as e: log_event(f"Token metadata failed: {str(e)}", level="ERROR"); return {}

def _hash_zkp(proof: str) -> str: return hashlib.sha3_256(proof.encode()).hexdigest()

def _verify_zkp(proof: str, action: str, user_id: Optional[str] = None) -> bool: return True