# backend/models/collaboration_data.py
# 🔒 Nuclear-Grade Collaboration Logger | Zero-Trust Architecture | GDPR-Compliant

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import time
import os
import uuid
import hmac
import hashlib
import asyncio
from collections import defaultdict
from motor.motor_asyncio import AsyncIOMotorClient

# 📦 Project Imports - CORRECTED PATHS
from db.mongo import get_mongo_client
from utils.logger import log_event
from security.intrusion_prevention.counter_response import BlackholeRouter
from security.firewall import Firewall as CollaborationFirewall
from security.blockchain.blockchain_utils import log_to_blockchain
from security.blockchain.zkp_handler import validate_zkp_token
from middlewares.rate_limiter import RateLimiter as CollaborationRateLimiter

# 🧱 Global Config
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "True").lower() == "true"
ENABLE_HONEYPOT = os.getenv("ENABLE_HONEYPOT", "True").lower() == "true"
ENABLE_ENDPOINT_MUTATION = os.getenv("ENABLE_ENDPOINT_MUTATION", "True").lower() == "true"
MIN_QUERY_TIME = float(os.getenv("MIN_QUERY_TIME", "0.1"))
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", 5))
DB_NAME = os.getenv("DB_NAME", "verbx")

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "collection": None,
    "firewall": CollaborationFirewall(),
    "threat_level": 0,
    "last_attack_time": 0,
    "rate_limiter": CollaborationRateLimiter()
}

# 🔒 Initialize Secure Collection
async def _get_secure_collection() -> AsyncIOMotorClient:
    hw_salt = os.getenv("HW_FINGERPRINT", "")
    collection_name = hmac.new(hw_salt.encode(), b"collaborations", hashlib.sha256).hexdigest()[:16]
    db_client = await get_mongo_client()
    return db_client[DB_NAME][collection_name]

async def init_collaboration_db():
    collection = await _get_secure_collection()
    SECURITY_CONTEXT["collection"] = collection
    try:
        await asyncio.gather(
            collection.create_index("user_pair_hash", unique=True, name="pair_hash_idx"),
            collection.create_index("timestamp", expireAfterSeconds=90 * 24 * 3600, name="ttl_idx"),
            collection.create_index([("user_a_hash", 1), ("timestamp", -1)], name="user_a_idx"),
            collection.create_index([("user_b_hash", 1), ("timestamp", -1)], name="user_b_idx")
        )
        log_event("Collaboration DB initialized", security=True)
    except Exception as e:
        log_event(f"DB init failed: {str(e)}", level="CRITICAL")
        raise RuntimeError("Secure initialization failed")

def _hash_user_id(user_id: str) -> str:
    salt = os.getenv("USER_HASH_SALT", "").encode()
    return hmac.new(salt, user_id.encode(), hashlib.sha3_256).hexdigest()

def _generate_entry_seal(user_a_hash: str, user_b_hash: str, timestamp: datetime) -> str:
    h = hmac.HMAC(os.getenv("ENTRY_SEAL_KEY", os.urandom(32)).encode(), (user_a_hash + user_b_hash + timestamp.isoformat()).encode(), hashlib.sha3_256)
    return h.hexdigest()

def _verify_entry_seal(doc: Dict[str, Any]) -> bool:
    expected = doc.get("_seal", "")
    computed = _generate_entry_seal(doc.get("user_a_hash", ""), doc.get("user_b_hash", ""), doc.get("timestamp"))
    return hmac.compare_digest(expected, computed)

async def _increment_threat_level():
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        await _anti_tamper_protocol()

async def _anti_tamper_protocol():
    log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
    if ENABLE_HONEYPOT:
        asyncio.create_task(_trigger_honeypot())
    await BlackholeRouter().trigger()
    if ENABLE_ENDPOINT_MUTATION:
        rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

async def _trigger_honeypot():
    await log_collaboration("attackerA", "attackerB", "fake_token")

async def log_collaboration(
    user_a: str,
    user_b: str,
    zkp_token: str
) -> Dict[str, bool]:
    if not await SECURITY_CONTEXT["rate_limiter"].check_limit(f"collab_log_{user_a}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")
    if not await validate_zkp_token(zkp_token, "collab_log", user_a):
        log_event("Invalid collab log attempt", level="WARNING")
        await _increment_threat_level()
        return {"success": False}

    if user_a == user_b:
        return {"success": False, "reason": "self_collab_not_allowed"}

    user_a_hash = _hash_user_id(user_a)
    user_b_hash = _hash_user_id(user_b)
    pair_hash = hmac.new(os.urandom(32), (user_a_hash + user_b_hash).encode(), hashlib.sha3_256).hexdigest()
    timestamp = datetime.utcnow()
    entry = {
        "user_a_hash": user_a_hash, "user_b_hash": user_b_hash, "pair_hash": pair_hash,
        "timestamp": timestamp, "_seal": _generate_entry_seal(user_a_hash, user_b_hash, timestamp),
        "session_id": str(uuid.uuid4())
    }

    try:
        result = await SECURITY_CONTEXT["collection"].update_one({"pair_hash": pair_hash}, {"$set": entry}, upsert=True)
        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain("collab_log", {"pair_hash": pair_hash, "timestamp": timestamp.isoformat(), "user_a": user_a_hash, "user_b": user_b_hash})
        log_event(f"Collaboration logged between {user_a_hash[:8]} and {user_b_hash[:8]}")
        return {"success": True, "new_entry": result.upserted_id is not None}
    except Exception as e:
        log_event(f"Collab log failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        raise

async def get_recent_collaborators(
    user_id: str,
    zkp_token: str,
    limit: int = 10,
    days: int = 30
) -> List[Dict[str, datetime]]:
    if not await validate_zkp_token(zkp_token, "collab_read", user_id):
        log_event("Unauthorized collab read attempt", level="WARNING")
        await _increment_threat_level()
        return []

    user_hash = _hash_user_id(user_id)
    cutoff = datetime.utcnow() - timedelta(days=days)
    start_time = time.time()
    collaborators = {}
    
    cursor_a = SECURITY_CONTEXT["collection"].find({"user_a_hash": user_hash, "timestamp": {"$gte": cutoff}}).sort("timestamp", -1).limit(limit)
    cursor_b = SECURITY_CONTEXT["collection"].find({"user_b_hash": user_hash, "timestamp": {"$gte": cutoff}}).sort("timestamp", -1).limit(limit)

    async for doc in cursor_a:
        other_hash = doc["user_b_hash"]
        if _verify_entry_seal(doc):
            collaborators[other_hash] = max(collaborators.get(other_hash, datetime.min), doc["timestamp"])

    async for doc in cursor_b:
        other_hash = doc["user_a_hash"]
        if _verify_entry_seal(doc):
            collaborators[other_hash] = max(collaborators.get(other_hash, datetime.min), doc["timestamp"])

    elapsed = time.time() - start_time
    if elapsed < MIN_QUERY_TIME:
        await asyncio.sleep(MIN_QUERY_TIME - elapsed)
    
    return [{"user_hash": uid, "last_interaction": ts} for uid, ts in sorted(collaborators.items(), key=lambda x: x[1], reverse=True)[:limit]]

async def clear_old_entries(zkp_token: str) -> Dict[str, int]:
    if not await validate_zkp_token(zkp_token, "db_maintenance"):
        log_event("Unauthorized collab cleanup", level="WARNING")
        return {"deleted": 0}

    cutoff = datetime.utcnow() - timedelta(days=90)
    try:
        shred_result = await SECURITY_CONTEXT["collection"].update_many({"timestamp": {"$lt": cutoff}}, {"$set": {"_shredded": True}})
        delete_result = await SECURITY_CONTEXT["collection"].delete_many({"timestamp": {"$lt": cutoff}})
        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain("collab_purge", {"cutoff": cutoff.isoformat(), "deleted": delete_result.deleted_count})
        log_event(f"Collaboration cleanup: {delete_result.deleted_count} entries deleted")
        return {"shredded": shred_result.modified_count, "deleted": delete_result.deleted_count}
    except Exception as e:
        log_event(f"Collab purge failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        raise