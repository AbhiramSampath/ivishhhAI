from pydantic import BaseModel, Field, validator
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from uuid import uuid4
import hashlib
import time
import unicodedata
import re
import os
import json
import asyncio
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

# Original imports (preserved) - CORRECTED PATHS
from utils.logger import log_event, security_alert
from security.blockchain.blockchain_utils import log_to_blockchain
from security.blockchain.zkp_handler import validate_session_token
from ivish_central.user_safety_center import has_user_consented
from db.redis import redis_db as redis_client
from db.mongo import consent_collection

# Security constants
MAX_CONSENT_AGE_DAYS = int(os.getenv("MAX_CONSENT_AGE_DAYS", "30"))
CONSENT_HMAC_KEY = os.getenv("CONSENT_HMAC_KEY", os.urandom(32)).encode()
CONSENT_CRYPTO_KEY = os.getenv("CONSENT_CRYPTO_KEY", os.urandom(32)).encode()
DEFAULT_CONSENT_TTL = int(os.getenv("DEFAULT_CONSENT_TTL", 86400 * 30))
BLOCKCHAIN_REVOCATION_ADDR = os.getenv("BLOCKCHAIN_REVOCATION_ADDR", "0xRevokeAddr")
BLACKLISTED_CONSENT_TOKENS = set()
INVALID_CHARS_PATTERN = re.compile(r'[\x00-\x1f\x7f-\x9f]')

_consent_killed = False

def _hmac_consent(data: Dict) -> str:
    h = hmac.HMAC(CONSENT_HMAC_KEY, hashes.SHA384(), backend=default_backend())
    h.update(json.dumps(data, sort_keys=True).encode())
    return h.finalize().hex()

class ConsentModel(BaseModel):
    user_id: str = Field(..., min_length=8, max_length=64, regex=r'^[a-zA-Z0-9_-]+$')
    allow_tracking: bool = Field(default=False)
    allow_memory: bool = Field(default=False)
    allow_voice_storage: bool = Field(default=False)
    consent_timestamp: datetime = Field(default_factory=datetime.utcnow)
    expiry: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(days=MAX_CONSENT_AGE_DAYS))
    device_id: Optional[str] = Field(None, min_length=6, max_length=64)
    version: str = Field("2.1", const=True)
    consent_token: str = Field(default_factory=lambda: str(uuid4()))
    consent_hmac: str = ""

    @validator('user_id')
    def validate_user_id(cls, v):
        if _consent_killed:
            raise ValueError("Consent system killed")
        if not v.isalnum():
            raise ValueError("User ID must be alphanumeric")
        return v

    @validator('device_id')
    def validate_device_id(cls, v):
        if _consent_killed:
            return v
        if v and not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Invalid device ID format")
        return v

    async def encrypt(self) -> bytes:
        if _consent_killed:
            return b''
        try:
            data = self.json(exclude={'version', 'consent_hmac'}).encode()
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(CONSENT_CRYPTO_KEY), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return nonce + encryptor.tag + ciphertext
        except Exception as e:
            security_alert(f"Consent encryption failed: {str(e)[:50]}")
            return b''

    @classmethod
    async def decrypt(cls, encrypted: bytes) -> Optional['ConsentModel']:
        if _consent_killed or not encrypted:
            return None
        try:
            if len(encrypted) < 28:
                return None
            nonce, tag, ciphertext = encrypted[:12], encrypted[12:28], encrypted[28:]
            cipher = Cipher(algorithms.AES(CONSENT_CRYPTO_KEY), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            return cls.parse_raw(decrypted)
        except Exception as e:
            security_alert(f"Consent decryption failed: {str(e)[:50]}")
            return None

    def validate_integrity(self) -> bool:
        if _consent_killed:
            return False
        expected_hmac = _hmac_consent(self.dict(exclude={'consent_hmac'}))
        return hmac.compare_digest(expected_hmac.encode(), self.consent_hmac.encode())

    def sign(self):
        self.consent_hmac = _hmac_consent(self.dict(exclude={'consent_hmac'}))
        return self

    class Config:
        schema_extra = {"example": {"user_id": "user1234", "allow_tracking": False, "allow_memory": True, "allow_voice_storage": False, "device_id": "device-xyz"}}

async def _get_consent_from_redis(user_id: str) -> Optional[ConsentModel]:
    if _consent_killed: return None
    try:
        encrypted = await redis_client.get(f"consent:{user_id}")
        if not encrypted: return None
        consent = await ConsentModel.decrypt(encrypted)
        if consent and consent.validate_integrity(): return consent
        return None
    except Exception as e:
        log_event(f"[SECURITY] Redis consent load failed: {str(e)}", level="error")
        return None

async def _store_consent_in_redis(consent: ConsentModel):
    if _consent_killed: return
    try:
        encrypted = await consent.encrypt()
        if not encrypted: return
        await redis_client.set(f"consent:{consent.user_id}", encrypted, ex=DEFAULT_CONSENT_TTL)
    except Exception as e:
        log_event(f"[SECURITY] Redis consent write failed: {str(e)}", level="error")

async def _get_consent_from_mongo(user_id: str) -> Optional[ConsentModel]:
    if _consent_killed: return None
    try:
        record = await consent_collection.find_one({"user_id": user_id})
        if not record: return None
        encrypted = record.get("encrypted_consent")
        consent = await ConsentModel.decrypt(encrypted)
        if consent and consent.validate_integrity(): return consent
        return None
    except Exception as e:
        log_event(f"[SECURITY] MongoDB consent load failed: {str(e)}", level="error")
        return None

async def _store_consent_in_mongo(consent: ConsentModel):
    if _consent_killed: return
    try:
        encrypted = await consent.encrypt()
        consent_hash = _hmac_consent(consent.dict(exclude={'consent_hmac'}))
        await consent_collection.update_one(
            {"user_id": consent.user_id},
            {"$set": {"encrypted_consent": encrypted, "consent_hash": consent_hash, "last_updated": datetime.utcnow()}},
            upsert=True
        )
    except Exception as e:
        log_event(f"[SECURITY] MongoDB consent write failed: {str(e)}", level="error")

async def update_consent(user_id: str, updates: dict, device_id: str = None, session_token: str = None) -> bool:
    if _consent_killed or not await validate_session_token(session_token): return False
    try:
        if not user_id or not isinstance(updates, dict):
            security_alert("Invalid consent update request"); return False
        
        consent = await _get_consent_from_redis(user_id) or await _get_consent_from_mongo(user_id)
        if not consent: consent = ConsentModel(user_id=user_id, device_id=device_id)

        valid_fields = {'allow_tracking', 'allow_memory', 'allow_voice_storage', 'expiry'}
        for field, value in updates.items():
            if field in valid_fields: setattr(consent, field, value)

        consent.consent_timestamp = datetime.utcnow()
        consent.expiry = consent.consent_timestamp + timedelta(days=30)
        consent.sign()

        await _store_consent_in_redis(consent)
        await _store_consent_in_mongo(consent)

        audit_payload = {
            "user_id": hashlib.sha256(user_id.encode()).hexdigest(), "action": "consent_update",
            "changes": updates, "timestamp": datetime.utcnow().isoformat(), "device_fingerprint": device_id
        }
        await log_to_blockchain(BLOCKCHAIN_REVOCATION_ADDR, audit_payload)
        log_event(f"Consent update for {user_id}", level="DEBUG", extra={"changes": updates})
        return True
    except Exception as e:
        security_alert(f"Consent update failed: {str(e)}"); return False

async def revoke_consent(user_id: str, session_token: str = None) -> bool:
    if _consent_killed or not await validate_session_token(session_token): return False
    try:
        if await redis_client.get(f"consent:{user_id}") is None: return False
        revocation_token = str(uuid4())
        audit_payload = {
            "user_id": hashlib.sha256(user_id.encode()).hexdigest(), "action": "consent_revoked",
            "timestamp": datetime.utcnow().isoformat(), "revocation_token": revocation_token
        }
        await log_to_blockchain(BLOCKCHAIN_REVOCATION_ADDR, audit_payload)
        await redis_client.delete(f"consent:{user_id}")
        await consent_collection.delete_one({"user_id": user_id})
        log_event(f"Consent nuclear wipe for {user_id}", level="GDPR")
        return True
    except Exception as e:
        security_alert(f"Consent revocation failed: {str(e)}"); return False

async def is_tracking_allowed(user_id: str, session_token: str = None) -> bool:
    if _consent_killed or not await validate_session_token(session_token): return False
    try:
        consent = await _get_consent_from_redis(user_id) or await _get_consent_from_mongo(user_id)
        if not consent or datetime.utcnow() > consent.expiry:
            if consent and datetime.utcnow() > consent.expiry: await revoke_consent(user_id)
            return False
        return consent.allow_tracking
    except Exception as e:
        security_alert(f"Consent check failed: {str(e)}"); return False

async def get_consent(user_id: str, session_token: str = None) -> Optional[ConsentModel]:
    if _consent_killed or not await validate_session_token(session_token): return None
    try:
        consent = await _get_consent_from_redis(user_id) or await _get_consent_from_mongo(user_id)
        if not consent or datetime.utcnow() > consent.expiry: return None
        return consent
    except Exception as e:
        security_alert(f"Consent retrieval failed: {str(e)}"); return None

def kill_consent():
    global _consent_killed
    _consent_killed = True
    log_event("Consent: Engine killed.", level="critical")