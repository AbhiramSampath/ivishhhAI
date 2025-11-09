# backend/app/routes/billing.py

import os
import uuid
import time
import hmac
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import logging
from fastapi import APIRouter, Request, Depends, HTTPException, Header, status
from pydantic import BaseModel, validator
from starlette.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_429_TOO_MANY_REQUESTS
from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis as AsyncRedis

# Internal imports - CORRECTED PATHS
from ..auth.jwt_handler import JWTHandler
from ..services.billing_service import get_usage_stats, get_plan, upgrade_plan
from utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain
from middlewares.rate_limiter import RateLimiter

# External imports - CORRECTED PATHS
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Type aliases
UserID = str
PlanTier = str
UsageStats = Dict[str, Any]
BillingEvent = Dict[str, Any]

# Security: Secrets and keys
_WEBHOOK_SECRET = os.getenv("BILLING_WEBHOOK_SECRET", "default_billing_secret").encode()
_STRIPE_VERSION = "2023-08-16"
_STRIPE_SIGNATURE_HEADER = "Stripe-Signature"

# --- Hardcoded constants (from non-existent config file) ---
PRICING_TIERS = {
    "free": {"api_calls": 100, "features": ["basic"], "price": 0},
    "pro": {"api_calls": 5000, "features": ["advanced"], "price": 10},
    "enterprise": {"api_calls": float('inf'), "features": ["all"], "price": 100},
}
_UPGRADE_RATE_LIMIT_CALLS = int(os.getenv("UPGRADE_RATE_LIMIT_CALLS", 3))
_UPGRADE_RATE_LIMIT_WINDOW = int(os.getenv("UPGRADE_RATE_LIMIT_WINDOW", 60))

router = APIRouter(
    prefix="/billing",
    tags=["billing"],
    dependencies=[Depends(get_current_user)]
)

class UpgradeRequest(BaseModel):
    """
    Payment upgrade request model with validation
    """
    plan: PlanTier
    payment_token: Optional[str]
    promo_code: Optional[str]

    @validator('plan')
    def validate_plan(cls, v):
        if v not in PRICING_TIERS:
            raise ValueError("Invalid plan tier")
        return v

class WebhookEvent(BaseModel):
    """
    Stripe/X.ai webhook event model
    """
    id: str
    type: str
    data: Dict
    created: int

class BillingStatusResponse(BaseModel):
    """
    Response model for billing status
    """
    plan: PlanTier
    usage: UsageStats
    limits: Dict
    audit: Dict[str, str]

rate_limiter = RateLimiter()

# === ROUTES === #
@router.get("/status", response_model=BillingStatusResponse)
async def billing_status(user: dict = Depends(get_current_user)):
    """
    Returns current subscription with cryptographic audit trail
    """
    plan = await get_plan(user["id"])
    usage = await get_usage_stats(user["id"])

    audit_hash = hashlib.sha256(
        f"{user['id']}{plan}{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()

    response = {
        "plan": plan,
        "usage": usage,
        "limits": PRICING_TIERS.get(plan, {}),
        "audit": {
            "hash": audit_hash,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    }

    await log_to_blockchain("billing_status", {
        "user_id": user["id"],
        "plan": plan,
        "usage": usage
    })

    return BillingStatusResponse(**response)

@router.post("/upgrade", status_code=status.HTTP_202_ACCEPTED)
async def upgrade_user_plan(request: UpgradeRequest, user: dict = Depends(get_current_user)):
    """
    Process plan upgrades with anti-fraud checks
    """
    user_id = user["id"]
    if not await rate_limiter.check_limit(user_id, rate=_UPGRADE_RATE_LIMIT_CALLS, window=_UPGRADE_RATE_LIMIT_WINDOW):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many upgrade attempts")

    result = await upgrade_plan(
        user_id=user_id,
        new_plan=request.plan,
        payment_token=request.payment_token,
        promo_code=request.promo_code
    )

    await log_to_blockchain("plan_upgrade", {
        "user_id": user_id,
        "new_plan": request.plan
    })

    return {"status": "processing", "request_id": result}

@router.get("/plans")
async def list_plans():
    """
    Return available plans with audit trail
    """
    log_event("Plans endpoint accessed")
    return {"plans": PRICING_TIERS}

@router.post("/webhook")
async def handle_billing_webhook(
    request: Request,
    stripe_signature: str = Header(None)
) -> Dict:
    """
    Hardened webhook handler with Stripe/X.ai verification
    """
    payload = await request.body()
    event_type = "unknown"

    if stripe_signature and "v1" in stripe_signature:
        event_type = "stripe"
        # The verification logic should be more robust, Stripe's official library is recommended
        # Placeholder for verification logic
        if "v1=" not in stripe_signature:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid webhook signature")
        
        signatures = stripe_signature.split(',')
        timestamp = signatures[0].split('=')[1]
        
        expected_sig = hmac.new(
            _WEBHOOK_SECRET,
            f"{timestamp}.{payload.decode()}".encode(),
            'sha256'
        ).hexdigest()
        
        valid_signature_found = False
        for sig in signatures:
            if sig.startswith('v1='):
                provided_sig = sig.split('=')[1]
                if hmac.compare_digest(provided_sig, expected_sig):
                    valid_signature_found = True
                    break
        
        if not valid_signature_found:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid webhook signature")
    else:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Unsupported billing vendor")

    try:
        event = WebhookEvent(**json.loads(payload))
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid webhook JSON")

    await log_to_blockchain("billing_webhook", {
        "event_id": event.id,
        "vendor": event_type,
        "event_type": event.type
    })

    return {"status": "processed", "event": event.type}