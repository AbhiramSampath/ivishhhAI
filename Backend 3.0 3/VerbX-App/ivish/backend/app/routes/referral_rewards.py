# backend/app/routes/referral_rewards.py

import os
import time
import uuid
import secrets
import hashlib
import hmac
import logging
import asyncio
import base64
import json
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument
from fastapi import APIRouter, Form, Request, HTTPException, Depends, status
from fastapi.security import APIKeyHeader

# 📦 Project Imports - CORRECTED PATHS
from db.mongo import users_collection, referral_collection, rewards_collection, get_mongo_client
from utils.logger import log_event
from security.threat_detector import is_suspicious_referral
from ..auth.jwt_handler import validate_user_session
from security.encryption_utils import encrypt_pii, decrypt_pii
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import BlackholeRouter
from middlewares.rate_limiter import RateLimiter
from security.device_fingerprint import validate_device_fingerprint

# 🧱 Hardcoded Config (from non-existent config file)
REFERRAL_REWARD_AMOUNT = int(os.getenv("REFERRAL_REWARD_AMOUNT", "100"))
REFERRAL_COOLDOWN_HOURS = int(os.getenv("REFERRAL_COOLDOWN_HOURS", "24"))
MAX_REDEEM_ATTEMPTS = int(os.getenv("REFERRAL_MAX_ATTEMPTS", "5"))
RATE_LIMIT_WINDOW = int(os.getenv("REFERRAL_RATE_LIMIT_WINDOW", "3600"))
MIN_PROCESSING_TIME_MS = int(os.getenv("REFERRAL_MIN_PROCESSING_TIME", "100"))
REFERRAL_CODE_LENGTH = int(os.getenv("REFERRAL_CODE_LENGTH", "8"))

# Initialize router
router = APIRouter(
    prefix="/referral",
    tags=["Referral"],
    dependencies=[Depends(APIKeyHeader(name="X-API-Key"))]
)

# Initialize secure components
logger = logging.getLogger(__name__)
blackhole = BlackholeRouter()
rate_limiter = RateLimiter()

def _hash_user_id(user_id: str) -> str:
    salt = os.getenv("USER_HASH_SALT")
    if not salt:
        log_event("CRITICAL: USER_HASH_SALT not set.", level="CRITICAL")
        salt = "default_salt"
    return hmac.new(salt.encode(), user_id.encode(), hashlib.sha3_256).hexdigest()

def _hash_referral_code(code: str) -> str:
    salt = os.getenv("REFERRAL_HMAC_KEY")
    if not salt:
        log_event("CRITICAL: REFERRAL_HMAC_KEY not set.", level="CRITICAL")
        salt = "default_salt"
    return hmac.new(salt.encode(), code.encode(), hashlib.sha3_256).hexdigest()

def _generate_secure_code(user_id: str) -> str:
    salt = secrets.token_bytes(16)
    code = hashlib.blake2b(f"{user_id}{salt}".encode(), digest_size=8).hexdigest().upper()
    return f"REF-{code}"

async def _apply_processing_delay(start_time: float, target_ms: int):
    elapsed_ms = (time.time() - start_time) * 1000
    if elapsed_ms < target_ms:
        await asyncio.sleep((target_ms - elapsed_ms) / 1000)

@router.post("/create")
async def create_referral(request: Request, user_id: str = Depends(validate_user_session)):
    start_time = time.time()
    if not await rate_limiter.check_limit(user_id, rate=MAX_REDEEM_ATTEMPTS, window=RATE_LIMIT_WINDOW):
        await blackhole.trigger()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")
    
    existing = await referral_collection.find_one({"user_id": user_id})
    if existing:
        return {"referral_code": existing["referral_code"]}

    referral_code = _generate_secure_code(user_id)
    hashed_code = _hash_referral_code(referral_code)

    referral_doc = {
        "user_id": user_id,
        "referral_code": hashed_code,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(days=30),
        "referrals": []
    }
    await referral_collection.insert_one(referral_doc)
    await log_to_blockchain("referral_created", {"user_id": user_id, "code_hash": hashed_code})
    await _apply_processing_delay(start_time, MIN_PROCESSING_TIME_MS)
    return {"referral_code": referral_code}

@router.post("/redeem")
async def redeem_referral(
    request: Request,
    new_user_id: str = Form(...),
    referral_code: str = Form(...),
    device_info: Dict = Form(...)
):
    start_time = time.time()
    if not await rate_limiter.check_limit(new_user_id, rate=MAX_REDEEM_ATTEMPTS, window=RATE_LIMIT_WINDOW):
        await blackhole.trigger()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")
    if not await validate_device_fingerprint(device_info):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Device verification failed")
    
    ref_entry = await referral_collection.find_one({"referral_code": _hash_referral_code(referral_code)})
    if not ref_entry:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Invalid referral code")
    referrer = ref_entry["user_id"]
    if new_user_id == referrer:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Self-referral prohibited")

    # Transactional logic using Motor's client
    client = await get_mongo_client()
    async with await client.start_session() as session:
        async with session.start_transaction():
            await referral_collection.update_one(
                {"referral_code": ref_entry["referral_code"]},
                {"$push": {"referrals": {"new_user_id": new_user_id, "timestamp": datetime.utcnow()}}},
                session=session
            )
            await rewards_collection.update_one(
                {"user_id": referrer},
                {"$inc": {"referral_credits": REFERRAL_REWARD_AMOUNT}},
                upsert=True,
                session=session
            )
            await rewards_collection.update_one(
                {"user_id": new_user_id},
                {"$inc": {"referral_credits": REFERRAL_REWARD_AMOUNT}},
                upsert=True,
                session=session
            )
    
    await log_to_blockchain("referral_redeemed", {
        "referrer": referrer, "referred": new_user_id, "reward": REFERRAL_REWARD_AMOUNT
    })
    await _apply_processing_delay(start_time, MIN_PROCESSING_TIME_MS)
    return {"status": "success", "reward": REFERRAL_REWARD_AMOUNT}

@router.get("/status/{user_id}")
async def get_referral_status(user_id: str, token: str = Depends(validate_user_session)):
    entry = await referral_collection.find_one({"user_id": user_id}, {"referrals": 1})
    if not entry:
        return {"total": 0, "referrals": []}
    
    return {"total": len(entry.get("referrals", [])), "referrals": entry.get("referrals", [])}

@router.get("/rewards/{user_id}")
async def get_rewards(user_id: str, token: str = Depends(validate_user_session)):
    reward = await rewards_collection.find_one({"user_id": user_id}, {"referral_credits": 1})
    return {"referral_credits": reward.get("referral_credits", 0) if reward else 0}