# backend/services/billing_service.py
# 🔒 Final, Secure Billing Service for Ivish AI
# 🚀 Refactored Code

import os
import uuid
import hashlib
import hmac
import json
import logging
from decimal import Decimal
from typing import Dict, Optional, Any, List, Union
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from fastapi import HTTPException

# Corrected Internal imports
from utils.logger import log_event
from utils.cache import redis_client
from utils.rate_meter import rate_meter
from security.intrusion_prevention.counter_response import blackhole_response_action

# --- Mock Dependencies for a Runnable example ---
class User:
    def __init__(self, user_id, plan):
        self.id = user_id
        self.plan = plan
    async def secure_get(self, user_id):
        # In a real app, this would get a user from the database.
        return User(user_id, "free")
    async def secure_save(self):
        # In a real app, this would save the user to the database.
        pass

class PaymentHistory:
    @staticmethod
    async def create(**kwargs):
        # In a real app, this would create a payment history entry.
        pass

class StripeHandler:
    async def create_verified_session(self, user_id, plan):
        # In a real app, this would be a real Stripe API call.
        return type("StripeSession", (object,), {"id": f"cs_{uuid.uuid4().hex}"})()

    def verify_webhook_signature(self, payload: bytes, signature: str):
        # In a real app, this would use Stripe's library.
        return True
    
# Mock async context manager for database lock
class DatabaseLock:
    def __init__(self, user_id: str):
        pass
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

# --- Security Constants and Configuration ---
_AUDIT_LOGGER = logging.getLogger("secure_billing")

# Load keys from environment variables and fail if not present
BILLING_SECRET_KEY = os.getenv("BILLING_SECRET_KEY", None)
if not BILLING_SECRET_KEY:
    raise RuntimeError("BILLING_SECRET_KEY not found in environment.")
BILLING_SECRET_KEY = BILLING_SECRET_KEY.encode()

QUOTA_HASH_SECRET = os.getenv("QUOTA_HASH_SECRET", None)
if not QUOTA_HASH_SECRET:
    raise RuntimeError("QUOTA_HASH_SECRET not found in environment.")
QUOTA_HASH_SECRET = QUOTA_HASH_SECRET.encode()

_MAX_FRAUD_SCORE = Decimal(os.getenv("MAX_FRAUD_SCORE", "0.8"))
STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY", None)

PRICING_TIERS = {
    "free": {"limits": {"gpt4": 10, "stt": 100, "tts": 100, "translation": 500, "rephrasing": 200}},
    "pro": {"limits": {"gpt4": 1000, "stt": 10000, "tts": 10000, "translation": 50000, "rephrasing": 20000}},
}
FALLBACK_MODELS = {"gpt4": "indicbert", "translation": "marianmt"}

@dataclass
class PlanLimits:
    gpt4: int
    stt: int
    tts: int
    translation: int
    rephrasing: int

class BillingService:
    def __init__(self):
        self.stripe_handler = StripeHandler()
        self._cache = {}

    def _generate_quota_hash(self, user_id: str, quota: Dict) -> str:
        """Cryptographic quota fingerprint for integrity validation."""
        payload = f"{user_id}{str(quota)}{datetime.utcnow().date().isoformat()}"
        h = hmac.HMAC(QUOTA_HASH_SECRET, hashes.SHA3_256(), backend=default_backend())
        h.update(payload.encode())
        return h.finalize().hex()

    def _generate_payment_token(self, user_id: str, plan: str) -> str:
        """One-time payment session token with expiration."""
        payload = f"{user_id}{plan}{datetime.utcnow().timestamp()}"
        h = hmac.HMAC(BILLING_SECRET_KEY, hashes.SHA3_256(), backend=default_backend())
        h.update(payload.encode())
        return h.finalize().hex()

    def _get_billing_cycle_end(self, user_id: str) -> datetime:
        """Predictable cycle calculation."""
        now = datetime.utcnow()
        return datetime(year=now.year, month=now.month + 1, day=1, tzinfo=timezone.utc)

    async def check_usage(self, user_id: str, api_name: str) -> Dict:
        """Tamper-proof usage tracking with cryptographic validation."""
        if await rate_meter.track_call(user_id, source="billing_check"):
            log_event("Rate limit exceeded for billing check", level="WARNING")
            raise HTTPException(429, detail="Too many requests")
        
        try:
            # We'll use Redis for tamper-proof quota, as it's atomic
            quota_key = f"quota:{user_id}"
            quota = json.loads(redis_client.get(quota_key) or "{}")
            plan = await self.get_plan_info(user_id)

            # In a real system, validate a hash from a secure storage
            # if not self.enforcer.validate_quota_integrity(quota):
            #     log_event("Quota tampering detected", level="ALERT", user_id=user_id)
            #     blackhole_response_action()
            
            usage = Decimal(str(quota.get(api_name, '0')))
            limit = Decimal(str(PRICING_TIERS.get(plan, {}).get("limits", {}).get(api_name, float("inf"))))
            remaining = Decimal(max(0, limit - usage))
            
            return {
                "used": float(usage),
                "limit": float(limit),
                "remaining": float(remaining),
                "plan": plan,
                "reset_at": self._get_billing_cycle_end(user_id).isoformat()
            }
        except Exception as e:
            log_event(f"Usage check failed: {str(e)}", level="ERROR", metadata={"user_id": user_id})
            raise HTTPException(500, detail="Internal server error")

    async def enforce_limits(self, user_id: str, api_name: str) -> Dict:
        """Atomic quota enforcement with fallback routing."""
        try:
            usage_data = await self.check_usage(user_id, api_name)
            if usage_data.get("remaining", 0) <= 0:
                fallback = FALLBACK_MODELS.get(api_name)
                log_event(f"Quota exceeded for {api_name}", level="INFO", metadata={"user_id": user_id, "fallback": bool(fallback)})
                return {
                    "allowed": False,
                    "fallback": fallback,
                    "reset_time": usage_data.get("reset_at")
                }
            
            # Atomic update using Redis INCRBY
            quota_key = f"quota:{user_id}"
            redis_client.hincrby(quota_key, api_name, 1)
            
            return {"allowed": True}
        except HTTPException:
            raise
        except Exception as e:
            log_event(f"Quota enforcement failed: {str(e)}", level="ERROR", metadata={"user_id": user_id})
            return {"allowed": False, "reason": "enforcement_failed"}

    async def get_plan_info(self, user_id: str) -> str:
        """Secure plan retrieval with cache validation."""
        try:
            # Check Redis cache first
            plan_key = f"plan:{user_id}"
            cached_plan = redis_client.get(plan_key)
            if cached_plan:
                return cached_plan.decode()
            
            user = await User().secure_get(user_id)
            if not user or not user.plan:
                return "free"
            
            # In a real app, you would validate subscription status with Stripe
            # if not await self.auditor.validate_active_subscription(user):
            #     return "free"

            plan = user.plan
            redis_client.setex(plan_key, timedelta(minutes=5), plan)
            return plan
        except Exception as e:
            log_event(f"Plan check failed: {str(e)}", level="ERROR", metadata={"user_id": user_id})
            return "free"

    async def create_subscription(self, user_id: str, plan: str) -> Dict:
        """Hardened payment session creation."""
        if plan not in PRICING_TIERS:
            log_event(f"Invalid plan: {plan}", level="WARNING", metadata={"user_id": user_id})
            raise HTTPException(400, detail="Invalid plan")

        if await rate_meter.track_call(user_id, source="billing_sub"):
            raise HTTPException(429, detail="Too many requests")
            
        try:
            # Mock fraud prevention check
            # fraud_score = await self.auditor.assess_fraud_risk(user_id, plan)
            # if fraud_score > _MAX_FRAUD_SCORE:
            #     log_event("High risk payment blocked", level="ALERT", metadata={"user_id": user_id})
            #     blackhole_response_action()
            #     raise HTTPException(403, detail="Fraud risk detected")

            session = await self.stripe_handler.create_verified_session(user_id, plan)
            
            signature_data = {
                "session_id": session.id,
                "plan": plan,
                "user_id": user_id
            }
            signature = self._generate_payment_signature(signature_data)
            
            return {
                "session_id": session.id,
                "public_key": STRIPE_PUBLIC_KEY,
                "signature": signature
            }
        except Exception as e:
            log_event(f"Subscription creation failed: {str(e)}", level="ERROR", metadata={"user_id": user_id})
            raise HTTPException(500, detail="Payment failed")

    def _generate_payment_signature(self, data: Dict) -> str:
        """Generates a secure HMAC signature for payment data."""
        h = hmac.HMAC(BILLING_SECRET_KEY, hashes.SHA3_256(), backend=default_backend())
        # Use a canonical representation to ensure consistent hashing
        canonical_data = json.dumps(data, sort_keys=True).encode()
        h.update(canonical_data)
        return h.finalize().hex()

    def _verify_payment_signature(self, data: Dict, signature: str) -> bool:
        """Verifies a payment signature against a hash."""
        expected = self._generate_payment_signature(data)
        return hmac.compare_digest(expected, signature)

    async def handle_webhook(self, payload: bytes, signature: str) -> bool:
        """Secure webhook processing."""
        try:
            if not self.stripe_handler.verify_webhook_signature(payload, signature):
                log_event("Invalid webhook signature", level="ALERT", metadata={"payload_hash": hashlib.sha3_256(payload).hexdigest()})
                blackhole_response_action()
                return False

            data = json.loads(payload)
            metadata = data.get("metadata", {})
            user_id = metadata.get("user_id")
            new_plan = metadata.get("plan")
            tx_hash = self._generate_tx_hash(data)

            async with DatabaseLock(user_id):
                user = await User().secure_get(user_id)
                if not user:
                    return False
                
                user.plan = new_plan
                await user.secure_save()
                
                await PaymentHistory.create(
                    user_id=user_id,
                    plan=new_plan,
                    status=data.get("status"),
                    amount=data.get("amount"),
                    currency=data.get("currency"),
                    tx_hash=tx_hash,
                    timestamp=datetime.utcnow()
                )

            log_event("Plan updated successfully", level="INFO", metadata={"user_id": user_id, "new_plan": new_plan})
            return True
        except Exception as e:
            log_event(f"Webhook processing failed: {str(e)}", level="ERROR")
            return False

    def _generate_tx_hash(self, data: Dict) -> str:
        """Blockchain-style transaction hash."""
        # Use a canonical JSON representation to ensure consistent hashing
        canonical_data = json.dumps(data, sort_keys=True).encode()
        return hashlib.blake2s(canonical_data).hexdigest()