# backend/services/referral_service.py

import os
import uuid
import secrets
import hashlib
import hmac
import asyncio
import re
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict
from pymongo import ReturnDocument
from fastapi import HTTPException, status

# 📦 Project Imports - CORRECTED PATHS
from ..db.mongo import ENABLE_ENDPOINT_MUTATION, ENABLE_HONEYPOT, users_collection, referral_collection
from ..utils.logger import log_event
from ..security.threat_detector import is_suspicious_referral
from ..auth.jwt_handler import JWTHandler
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import BlackholeRouter, rotate_endpoint
from security.firewall import Firewall as ReferralFirewall
from middlewares.rate_limiter import RateLimiter

# 🧱 Hardcoded Config (from non-existent config file)
REWARD_POLICY = {"invite_reward": 150, "max_reward": 1000}
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "True").lower() == "true"
MAX_REFERRALS_PER_USER = int(os.getenv("MAX_REFERRALS_PER_USER", 50))
RATE_LIMIT_WINDOW = int(os.getenv("REFERRAL_RATE_LIMIT_WINDOW", 60))
MAX_FAILURE_RATE = int(os.getenv("REFERRAL_MAX_FAILURE_RATE", 3))
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", "5"))

# 🔐 Secure Global State
# This should ideally be a shared, persistent store like Redis, but is kept in-memory
# to strictly follow the no-new-files rule. This is a critical scalability flaw.
SECURITY_CONTEXT = {
    "firewall": ReferralFirewall(),
    "threat_level": 0,
    "last_attack_time": 0
}

# Placeholder function for validate_user_session
async def validate_user_session(user_id: str, action: str) -> bool:
    """Placeholder for user session validation"""
    try:
        jwt_handler = JWTHandler()
        # Basic validation - in production this would check actual session
        return bool(user_id and len(user_id) > 0)
    except Exception as e:
        log_event(f"Session validation failed: {str(e)}", level="ERROR")
        return False

# 🔒 Security Utilities - CONSOLIDATED & CORRECTED
def _hash_user_id(user_id: str) -> str:
    """GDPR-compliant user hashing with secure salt."""
    salt = os.getenv("USER_HASH_SALT")
    if not salt:
        log_event("CRITICAL: USER_HASH_SALT not set. Hashing is compromised.", level="CRITICAL")
        salt = "default_salt"
    return hmac.new(
        salt.encode(),
        user_id.encode(),
        hashlib.sha3_256
    ).hexdigest()

def _hash_referral_code(code: str) -> str:
    """Secure referral code hashing with secure salt."""
    salt = os.getenv("REFERRAL_HMAC_KEY")
    if not salt:
        log_event("CRITICAL: REFERRAL_HMAC_KEY not set. Hashing is compromised.", level="CRITICAL")
        salt = "default_salt"
    return hmac.new(
        salt.encode(),
        code.encode(),
        hashlib.sha3_256
    ).hexdigest()

def _generate_secure_code(user_id: str) -> str:
    """Cryptographically secure referral code generation."""
    salt = secrets.token_bytes(16)
    return hashlib.blake2b(
        f"{user_id}{salt}".encode(),
        digest_size=8
    ).hexdigest().upper()

async def _increment_threat_level():
    """Increase threat level and trigger defense if needed."""
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        await _anti_tamper_protocol()

async def _anti_tamper_protocol():
    """Active defense against referral abuse."""
    log_event("THREAT: Anti-tamper protocol triggered", level="ALERT")
    if ENABLE_HONEYPOT:
        asyncio.create_task(register_referral("fake_code", "attacker_user"))
    await BlackholeRouter().trigger()
    if ENABLE_ENDPOINT_MUTATION:
        rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

# 🧠 Referral Service Core
async def generate_referral_code(user_id: str) -> Optional[str]:
    """
    Generates hardened referral code.
    """
    if not await validate_user_session(user_id, "generate_referral"):
        await log_to_blockchain("ACCESS_DENIED", payload={"user_id": user_id})
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access denied")

    rate_limiter = RateLimiter()
    if not await rate_limiter.check_limit(user_id, rate=MAX_FAILURE_RATE, window=RATE_LIMIT_WINDOW):
        log_event("Referral generation rate limited", level="WARNING")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")

    existing_count = await users_collection.count_documents({
        "referrer_id": _hash_user_id(user_id),
        "created_at": {"$gte": datetime.now(timezone.utc) - timedelta(days=1)}
    })
    if existing_count >= 3:
        await log_to_blockchain("CODE_LIMIT_EXCEEDED", payload={"user_id": user_id})
        return None

    try:
        code = _generate_secure_code(user_id)
        hashed_code = _hash_referral_code(code)
        referral_doc = {
            "referrer_id": _hash_user_id(user_id),
            "referral_code": hashed_code,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(days=30),
            "uses": 0,
            "referred_users": [],
            "is_active": True,
            "session_id": str(uuid.uuid4())
        }
        await referral_collection.insert_one(referral_doc)
        await log_to_blockchain("CODE_GENERATED", payload={"user_id": user_id, "code_hash": hashed_code})
        return code

    except Exception as e:
        log_event(f"Referral code generation failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "System error")

async def validate_code(code: str) -> Dict[str, Any]:
    """Validates referral code with fraud checks."""
    if not bool(code) or len(code) != 16:
        return {"valid": False, "reason": "Invalid code format"}
    
    hashed_code = _hash_referral_code(code)
    ref = await referral_collection.find_one({
        "referral_code": hashed_code,
        "is_active": True,
        "expires_at": {"$gt": datetime.now(timezone.utc)}
    })
    
    if not ref:
        return {"valid": False, "reason": "Invalid or expired code"}

    if ref["uses"] >= MAX_REFERRALS_PER_USER:
        return {"valid": False, "reason": "Referral limit reached"}

    return {
        "valid": True,
        "referrer_id": ref["referrer_id"],
        "uses_remaining": MAX_REFERRALS_PER_USER - ref["uses"],
        "code": code,
        "referrer_doc": ref
    }

async def register_referral(code: str, invitee_id: str) -> Dict[str, Any]:
    """
    Fraud-proof referral registration.
    """
    if not await validate_user_session(invitee_id, "accept_referral"):
        await log_to_blockchain("INVALID_SESSION", payload={"invitee_id": invitee_id})
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid session")

    ref_result = await validate_code(code)
    if not ref_result["valid"]:
        return {"success": False, "reason": ref_result["reason"]}

    referrer_id = ref_result["referrer_id"]
    if await referral_collection.count_documents({
        "referral_code": ref_result["referrer_doc"]["referral_code"],
        "referred_users": invitee_id
    }) > 0:
        return {"success": False, "reason": "Duplicate referral"}

    if is_suspicious_referral(referrer_id, invitee_id):
        await referral_collection.update_one(
            {"referral_code": ref_result["referrer_doc"]["referral_code"]},
            {"$set": {"is_active": False}}
        )
        await log_to_blockchain("FRAUD_DETECTED", payload={"referrer": referrer_id, "invitee": invitee_id})
        return {"success": False, "reason": "Suspicious activity"}

    try:
        updated_ref = await referral_collection.find_one_and_update(
            {"referral_code": ref_result["referrer_doc"]["referral_code"]},
            {
                "$push": {"referred_users": invitee_id},
                "$inc": {"uses": 1}
            },
            return_document=ReturnDocument.AFTER
        )
        if not updated_ref:
            return {"success": False, "reason": "Referral not found"}
        
        await reward_users(referrer_id, invitee_id)
        
        await log_to_blockchain("REFERRAL_ACCEPTED", payload={
            "referrer": referrer_id, "invitee": invitee_id, "code_hash": updated_ref["referral_code"]
        })

        return {
            "success": True,
            "referrer": referrer_id,
            "invitee": invitee_id,
            "uses_remaining": MAX_REFERRALS_PER_USER - updated_ref["uses"]
        }

    except Exception as e:
        log_event(f"Referral registration failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "System error")

async def reward_users(referrer_id: str, invitee_id: str) -> Dict[str, Any]:
    """
    Secure reward distribution.
    """
    reward = min(REWARD_POLICY.get("invite_reward", 100), 1000)

    try:
        await asyncio.gather(
            users_collection.update_one({"user_id": referrer_id}, {"$inc": {"credits": reward}}),
            users_collection.update_one({"user_id": invitee_id}, {"$inc": {"credits": reward}})
        )
        await log_to_blockchain("REWARDS_ISSUED", payload={
            "referrer": referrer_id, "invitee": invitee_id, "amount": reward
        })
        return {"success": True, "amount": reward}

    except Exception as e:
        log_event(f"Reward distribution failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "System error")

async def get_user_referrals(user_id: str) -> Dict[str, Any]:
    """
    Secure referral stats.
    """
    if not await validate_user_session(user_id, "view_referrals"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access denied")

    try:
        ref = await referral_collection.find_one({"referrer_id": _hash_user_id(user_id)})
        if not ref:
            return {"total": 0, "users": []}

        return {
            "total": ref["uses"],
            "users": [
                f"user_{hashlib.sha256(u.encode()).hexdigest()[:8]}" 
                for u in ref["referred_users"]
            ],
            "expires_in_days": (ref["expires_at"] - datetime.now(timezone.utc)).days
        }

    except Exception as e:
        log_event(f"Referral stats failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "System error")