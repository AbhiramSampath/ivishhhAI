"""
🧠 Ivish AI Billing & Credit Module
🔐 Manages usage tracking, credit deduction, plan upgrades, and secure metering
📦 Supports: GPT, STT, TTS, Translation, NER, Emotion, etc.
🛡️ Features: ZKP access, tamper-evident logs, blockchain micropayments, rate limiting
"""

import hmac
import os
import re
import uuid
import json
import asyncio
import logging
from decimal import Decimal, getcontext
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache

# 🔐 Security Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# 📁 Project Imports - CORRECTED PATHS
from backend.app.services.billing_service import PRICING_RULES
from utils.logger import log_event
from db.mongo import get_billing_collection
from security.blockchain.zkp_handler import verify_billing_access, ZKPAuthenticator
from security.blockchain.blockchain_utils import log_microtransaction
from middlewares.rate_limiter import RateLimiter as BillingRateLimiter
from security.intrusion_prevention.counter_response import BlackholeRouter

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("BILLING_HMAC_KEY", os.urandom(32)).encode()
_SALT = os.urandom(16)
_KDF_ITERATIONS = 100000
_LATENCY_BUDGET_MS = 150
_SUPPORTED_FEATURES = ['stt', 'tts', 'gpt', 'translate', 'ner', 'emotion', 'context']
_MIN_CREDITS = Decimal("0.01")
_MAX_TOPUP = 10000
_MAX_ATTEMPTS = 5

getcontext().prec = 50

@dataclass
class BillingRecord:
    user_id: str
    feature: str
    cost: float
    timestamp: str
    _signature: Optional[str] = None

class SecureBillingEngine:
    def __init__(self):
        self._rate_limiter = BillingRateLimiter(max_calls=100)
        self._breach_attempts = {}
        self._blackhole = BlackholeRouter()
    
    def _sign_record(self, record: Dict) -> str:
        h = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        h.update(json.dumps(record, sort_keys=True).encode())
        return h.finalize().hex()

    def _generate_nonce(self) -> str:
        return os.urandom(16).hex()

    async def log_usage(self, user_id: str, feature: str):
        try:
            if not await self._verify_access(user_id):
                await self._handle_malicious_usage(user_id)
                return

            sanitized_feature = self._sanitize_feature(feature)
            today = datetime.utcnow().date().isoformat()
            collection = await get_billing_collection()
            usage_key = f"usage.{sanitized_feature}"
            result = await collection.update_one(
                {"user_id": user_id, "date": today},
                {"$inc": {usage_key: 1}},
                upsert=True
            )

            if not result.acknowledged:
                await self._handle_db_tampering(user_id)
                return

            await log_event(f"BILLING_USAGE | {user_id[:6]}... used {sanitized_feature}")
            await log_microtransaction(user_id, "usage", 1, sanitized_feature)
        except Exception as e:
            await log_event(f"BILLING_USAGE_FAILURE: {str(e)}")
            return

    async def _verify_access(self, user_id: str) -> bool:
        return await verify_billing_access(user_id)

    async def deduct_credits(self, user_id: str, feature: str) -> Dict:
        try:
            if not await self._verify_access(user_id):
                await self._handle_malicious_usage(user_id)
                return {"balance": 0.0, "status": "locked"}
            
            sanitized_feature = self._sanitize_feature(feature)
            cost = Decimal(str(PRICING_RULES.get(sanitized_feature, 0.0)))
            
            collection = await get_billing_collection()
            async with await collection.client.start_session() as session:
                async with session.start_transaction():
                    user_doc = await collection.find_one({"user_id": user_id}, session=session)
                    current_balance = Decimal(str(user_doc.get("balance", 0.0)))
                    
                    if current_balance < cost:
                        await self.auto_disable_features(user_id)
                        raise ValueError("Insufficient credits")
                    
                    new_balance = current_balance - cost
                    if new_balance < Decimal("0"):
                        await self._handle_db_tampering(user_id)
                        raise RuntimeError("Balance validation failed")
                    
                    await collection.update_one(
                        {"user_id": user_id},
                        {"$set": {"balance": float(new_balance)}},
                        session=session
                    )
                    
                    await log_event(f"CREDITS_DEDUCTED | {user_id} - {sanitized_feature}: {cost}")
                    await log_microtransaction(user_id, "deduct", float(cost), sanitized_feature)
                    
                    return {"balance": float(new_balance), "feature": sanitized_feature, "cost": float(cost), "timestamp": datetime.now().isoformat(), "status": "success"}
        except Exception as e:
            await log_event(f"CREDIT_DEDUCTION_FAILURE: {str(e)}")
            return {"balance": 0.0, "status": "failure"}

    async def get_usage_summary(self, user_id: str) -> Dict[str, Any]:
        try:
            collection = await get_billing_collection()
            pipeline = [{"$match": {"user_id": user_id}}, {"$project": {"_id": 0, "date": 1, "usage": {"$filter": {"input": {"$objectToArray": "$usage"}, "as": "item", "cond": {"$ne": ["$$item.v", 0]}}}}}]
            return await collection.aggregate(pipeline).to_list(length=1000)
        except Exception as e:
            await log_event(f"USAGE_SUMMARY_FAILURE: {str(e)}")
            return {"error": str(e)}

    async def check_balance(self, user_id: str) -> Dict:
        try:
            collection = await get_billing_collection()
            doc = await collection.find_one({"user_id": user_id}, projection={"balance": 1, "status": 1, "_id": 0})
            if not doc:
                return {"balance": 0.0, "status": "locked", "error": "User not found"}
            
            return {
                "balance": float(doc.get("balance", 0.0)),
                "status": doc.get("status", "limited"),
                "timestamp": datetime.now().isoformat(),
                "_signature": self._sign_record(doc)
            }
        except Exception as e:
            await log_event(f"BALANCE_CHECK_FAILURE: {str(e)}")
            return {"balance": 0.0, "status": "locked", "error": "Failed"}

    async def auto_disable_features(self, user_id: str):
        try:
            collection = await get_billing_collection()
            await collection.update_one({"user_id": user_id}, {"$set": {"status": "limited", "downgraded_at": datetime.utcnow()}})
            await log_event(f"BILLING_DOWNGRADE | {user_id}", level="WARNING")
        except Exception as e:
            await log_event(f"FEATURE_DISABLE_FAILURE: {str(e)}")

    async def top_up_credits(self, user_id: str, amount: float):
        try:
            if not 0 < amount <= _MAX_TOPUP:
                raise ValueError("Invalid top-up amount")
            
            collection = await get_billing_collection()
            async with await collection.client.start_session() as session:
                async with session.start_transaction():
                    result = await collection.update_one({"user_id": user_id}, {"$inc": {"balance": float(Decimal(str(amount)))}}, upsert=True, session=session)
                    if result.modified_count == 0 and not result.upserted_id:
                        raise RuntimeError("Top-up failed")
            
            await log_microtransaction(user_id, "topup", amount, "admin")
            await log_event(f"CREDITS_TOPUP | {user_id[:6]}... +{amount}")
            
            return {"status": "success", "balance": await self.check_balance(user_id)}
        except Exception as e:
            await log_event(f"CREDIT_TOPUP_FAILURE: {str(e)}")
            return {"status": "failure", "error": str(e)}

    def _sanitize_feature(self, feature: str) -> str:
        if feature not in _SUPPORTED_FEATURES:
            raise ValueError(f"Unsupported feature: {feature}")
        return feature

    async def _verify_access(self, user_id: str) -> bool:
        if not await self._rate_limiter.check_limit(user_id):
            await log_event(f"BILLING_RATE_LIMIT | {user_id}", level="WARNING")
            return False
        return await verify_billing_access(user_id)

    async def _handle_malicious_usage(self, user_id: str):
        self._breach_attempts[user_id] = self._breach_attempts.get(user_id, 0) + 1
        if self._breach_attempts[user_id] > _MAX_ATTEMPTS:
            await self._trigger_defense_response(user_id)

    async def _handle_db_tampering(self, user_id: str):
        await log_event(f"BILLING_DB_TAMPER_DETECTED: {user_id}")
        await self._trigger_defense_response(user_id)

    async def _trigger_defense_response(self, user_id: str):
        logging.critical(f"🚨 BILLING TAMPERING DETECTED: {user_id}")
        ZKPAuthenticator().rotate_keys()
        await self._blackhole.trigger()

    async def _fetch_stripe_plan(self, user_id: str) -> str:
        return "premium"
    
    async def sync_plan_from_stripe(self, user_id: str):
        try:
            plan = await self._fetch_stripe_plan(user_id)
            collection = await get_billing_collection()
            await collection.update_one({"user_id": user_id}, {"$set": {"plan": plan, "plan_synced_at": datetime.utcnow()}})
            await log_event(f"STRIPE_PLAN_SYNC | {user_id} -> {plan}")
        except Exception as e:
            await log_event(f"STRIPE_SYNC_FAILURE: {str(e)}")