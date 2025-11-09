# backend/db/mongo.py
# 🔒 Nuclear-Grade MongoDB Access Layer | Zero-Trust Architecture | GDPR-Compliant

import motor.motor_asyncio
from datetime import datetime, timedelta
import time
import os
import uuid
import hmac
import hashlib
import asyncio
import logging
import json
from typing import Dict, Any, Optional, List
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 📦 Project Imports - CORRECTED PATHS
from db.connection import MONGO_URI, DB_NAME
from utils.logger import log_event
from security.encryption_utils import encrypt_data, decrypt_data
from security.blockchain.blockchain_utils import log_to_blockchain, secure_audit_log
from security.intrusion_prevention.counter_response import BlackholeRouter, rotate_endpoint
from security.firewall import Firewall as MongoFirewall
from middlewares.rate_limiter import RateLimiter

# 🧱 Global Config - Defined locally as config file is not in PDF
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "True").lower() == "true"
ENABLE_HONEYPOT = os.getenv("ENABLE_HONEYPOT", "True").lower() == "true"
ENABLE_ENDPOINT_MUTATION = os.getenv("ENABLE_ENDPOINT_MUTATION", "True").lower() == "true"
MAX_DOCUMENT_SIZE = 1024 * 1024
MIN_QUERY_TIME = 0.1
DOCUMENT_SEAL_KEY = os.getenv("DOC_SEAL_KEY", "default_seal_key").encode()
MONGO_HMAC_KEY = os.getenv("MONGO_HMAC_KEY", "default_hmac_key").encode()
HW_FINGERPRINT = os.getenv("HARDWARE_ID", "default_hw")
PSEUDONYM_SALT = os.getenv("PSEUDONYM_SALT", "default_salt")

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "client": None,
    "db": None,
    "collection_seals": {},
    "firewall": MongoFirewall(),
    "threat_level": 0,
    "last_attack_time": 0,
    "rate_limiter": RateLimiter()
}

# 🔒 Initialize MongoDB Client
def _get_secure_uri() -> str:
    return MONGO_URI

CLIENT = motor.motor_asyncio.AsyncIOMotorClient(_get_secure_uri())
DB = CLIENT[DB_NAME]
SECURITY_CONTEXT["client"] = CLIENT
SECURITY_CONTEXT["db"] = DB
AES_KEY = os.getenv("MONGO_AES_KEY", os.urandom(32)).encode()

def _generate_document_seal(user_id: str, data: Any) -> str:
    return hmac.new(DOCUMENT_SEAL_KEY, (user_id + str(data)).encode(), hashlib.sha3_256).hexdigest()

def _verify_document_seal(doc: Dict[str, Any]) -> bool:
    expected = doc.get("_seal", "")
    computed = _generate_document_seal(doc.get("user_id"), doc.get("data"))
    return hmac.compare_digest(expected, computed)

def _hash_user_id(user_id: str) -> str:
    return hashlib.shake_256(user_id.encode() + PSEUDONYM_SALT.encode()).hexdigest(16)

def _pseudonymize_user(user_id: str) -> str:
    return hashlib.sha256(user_id.encode() + PSEUDONYM_SALT.encode()).hexdigest()

async def init_db() -> None:
    try:
        await asyncio.gather(
            DB.sessions.create_index("expiry", expireAfterSeconds=0, name="ttl_idx"),
            DB.consent_logs.create_index([("timestamp", 1), ("user_id", 1)], name="audit_idx"),
            DB.user_profiles.create_index("user_id", unique=True, partialFilterExpression={"user_id": {"$exists": True}})
        )
        for col in ["sessions", "consent_logs", "user_profiles"]:
            SECURITY_CONTEXT['collection_seals'][col] = await _generate_collection_seal(col)
        log_event("MongoDB initialized with hardened security", security=True)
    except Exception as e:
        log_event(f"DB init failed: {str(e)}", level="CRITICAL")
        raise RuntimeError("Secure initialization failed")

async def _generate_collection_seal(collection_name: str) -> str:
    cols = await DB.list_collection_names()
    if collection_name not in cols: return ""
    stats = await DB.command("collstats", collection_name)
    seal = hmac.new(os.urandom(32), str(stats).encode(), hashlib.sha512).hexdigest()
    return seal

async def insert_session_data(user_id: str, session_payload: Dict[str, Any], request_token: str) -> str:
    if not SECURITY_CONTEXT['rate_limiter'].check_limit(user_id):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")
    session_id = str(uuid.uuid4())
    encrypted = encrypt_data(session_payload, hardware_bound=True)
    doc = {"_id": session_id, "user_id": _pseudonymize_user(user_id), "data": encrypted, "created_at": datetime.utcnow(), "expiry": datetime.utcnow() + timedelta(minutes=30), "_seal": _generate_document_seal(user_id, session_payload), "_hw_fingerprint": HW_FINGERPRINT}
    try:
        result = await DB.sessions.insert_one(doc)
        if not result.acknowledged: raise RuntimeError("Write not acknowledged")
        if ENABLE_BLOCKCHAIN_LOGGING: await log_to_blockchain("session_write", {"user_id_hash": _hash_user_id(user_id), "session_id": session_id, "timestamp": datetime.utcnow().isoformat()})
        return session_id
    except Exception as e:
        log_event(f"Session insert failed: {str(e)}", level="ERROR")
        raise

async def get_user_phrasebook(user_id: str, request_token: str) -> List[Dict[str, Any]]:
    if not SECURITY_CONTEXT['rate_limiter'].check_limit(user_id):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")
    pseudonym = _pseudonymize_user(user_id)
    start = time.monotonic()
    result = await DB.user_profiles.find_one({"user_id": pseudonym})
    elapsed = time.monotonic() - start
    if elapsed < MIN_QUERY_TIME: await asyncio.sleep(MIN_QUERY_TIME - elapsed)
    if not result: return []
    if not _verify_document_seal(result): log_event("Phrasebook tampering detected", level="CRITICAL"); raise RuntimeError("Data integrity check failed")
    try:
        decrypted = decrypt_data(result.get("phrasebook", []))
        return decrypted
    except Exception as e:
        log_event(f"Decryption failed: {str(e)}", level="ERROR"); raise

async def log_consent(user_id: str, details: Dict[str, Any], request_token: str) -> None:
    if not SECURITY_CONTEXT['rate_limiter'].check_limit(user_id):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")
    pseudonym = _pseudonymize_user(user_id)
    log = {"log_id": str(uuid.uuid4()), "user_id_hash": _hash_user_id(user_id), "timestamp": datetime.utcnow(), "details": details, "device_fingerprint": pseudonym, "_seal": _generate_document_seal(user_id, details), "_hw_fingerprint": HW_FINGERPRINT}
    try:
        insert_result = await DB.consent_logs.insert_one(log)
        if not insert_result.acknowledged: raise RuntimeError("Consent log write failed")
        if ENABLE_BLOCKCHAIN_LOGGING: await log_to_blockchain("consent_log", log)
    except Exception as e:
        log_event(f"Consent log failed: {str(e)}", level="CRITICAL"); raise

async def delete_user_data(user_id: str, request_token: str) -> Dict[str, bool]:
    if not SECURITY_CONTEXT['rate_limiter'].check_limit(user_id):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")
    pseudonym = _pseudonymize_user(user_id)
    results = {}
    shred_update = {"$set": {"data": os.urandom(128), "phrasebook": [os.urandom(64)], "_shredded": True}}
    profile_update = await DB.user_profiles.update_one({"user_id": pseudonym}, shred_update)
    session_delete = await DB.sessions.delete_many({"user_id": pseudonym})
    consent_update = await DB.consent_logs.update_many({"user_id_hash": _hash_user_id(user_id)}, {"$set": {"_shredded": True}})
    if ENABLE_BLOCKCHAIN_LOGGING: await log_to_blockchain("user_wipe", {"user_id_hash": _hash_user_id(user_id), "timestamp": datetime.utcnow().isoformat(), "shred_verified": all([profile_update.modified_count > 0, session_delete.deleted_count > 0, consent_update.modified_count > 0])})
    return {"sessions_deleted": session_delete.deleted_count, "profile_shredded": profile_update.modified_count > 0, "consents_marked": consent_update.modified_count}

async def get_active_sessions(user_id: str) -> List[Dict[str, Any]]:
    pseudonym = _pseudonymize_user(user_id)
    now = datetime.utcnow()
    try:
        cursor = DB.sessions.find({"user_id": pseudonym, "expiry": {"$gte": now}})
        results = [doc async for doc in cursor]
        return [decrypt_data(doc.get("data")) for doc in results if _verify_document_seal(doc)]
    except Exception as e:
        log_event(f"Session fetch failed: {str(e)}", level="ERROR"); raise

async def wipe_expired_sessions():
    now = datetime.utcnow()
    try:
        result = await DB.sessions.delete_many({"expiry": {"$lt": now}})
        if result.deleted_count > 0: log_event(f"Expired {result.deleted_count} sessions")
    except Exception as e:
        log_event(f"Session wipe failed: {str(e)}", level="ERROR"); raise