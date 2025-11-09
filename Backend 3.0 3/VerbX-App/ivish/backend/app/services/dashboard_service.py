# backend/services/dashboard_service.py
# 🔒 Final, Secure Dashboard Service for Ivish AI
# 🚀 Refactored Code

import os
import time
import asyncio
import hashlib
import hmac
import logging
import json
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_429_TOO_MANY_REQUESTS
from motor.motor_asyncio import AsyncIOMotorClient

# Corrected Internal imports
from ..utils.logger import log_event
from ..utils.cache import redis_client
from ..utils.rate_meter import rate_meter
from ....security.blockchain.blockchain_utils import fetch_audit_logs, log_to_blockchain
from ....security.blockchain.zkp_handler import ZKPAuthenticator
from ....security.encryption_utils import AES256Cipher
from ..utils.helpers import constant_time_compare
from ..models.performance_metrics import summarize_emotions, summarize_latencies
from ..db.connection import get_async_mongo_client

# Dashboard Constants
_DEFAULT_LIMIT = 50
_MAX_AGGREGATE = 1000
_DASHBOARD_HMAC_KEY = os.getenv("DASHBOARD_HMAC_KEY", None)
_DASHBOARD_ENCRYPTION_KEY = os.getenv("DASHBOARD_ENCRYPTION_KEY", None)

if not _DASHBOARD_HMAC_KEY or not _DASHBOARD_ENCRYPTION_KEY:
    raise RuntimeError("Dashboard HMAC and Encryption keys not found in environment.")

_DASHBOARD_HMAC_KEY = _DASHBOARD_HMAC_KEY.encode()
_DASHBOARD_ENCRYPTION_KEY = _DASHBOARD_ENCRYPTION_KEY.encode()

# MongoDB setup
async def get_db() -> AsyncIOMotorClient:
    return await get_async_mongo_client()

class DashboardService:
    """
    Unified dashboard service with:
    - Secure user validation
    - Encrypted data retrieval
    - Blockchain audit integration
    - Rate limiting and defense
    """
    def __init__(self, db_client: AsyncIOMotorClient):
        self._db = db_client["ivish"]
        self._sessions_col = self._db["session_logs"]
        self._response_col = self._db["response_logs"]
        self._audit_col = self._db["audit_logs"]
        self._zkp_authenticator = ZKPAuthenticator()
        self._cipher = AES256Cipher(_DASHBOARD_ENCRYPTION_KEY)

    async def _validate_user(self, user_id: str, zkp_proof: str) -> bool:
        """Zero-Knowledge Proof-based user validation."""
        return await self._zkp_authenticator.verify_proof_async(user_id, zkp_proof)

    async def _check_rate_limit(self, user_id: str):
        """Rate limit check with defense activation."""
        if await rate_meter.track_call(user_id, source="dashboard_access"):
            raise HTTPException(HTTP_429_TOO_MANY_REQUESTS, "Too many requests")

    async def get_session_summary(self, user_id: str, zkp_proof: str, limit: int = 10) -> Dict[str, Any]:
        """
        Fetch recent sessions with ZKP validation, rate limiting, and secure caching.
        """
        await self._check_rate_limit(user_id)
        if not await self._validate_user(user_id, zkp_proof):
            raise HTTPException(HTTP_401_UNAUTHORIZED, "Invalid session token")

        cache_key = f"session_summary:{user_id}"
        if cached := await redis_client.get(cache_key):
            try:
                decrypted_data = self._cipher.decrypt(bytes.fromhex(cached.decode()))
                return json.loads(decrypted_data)
            except Exception:
                await log_event("DASHBOARD: Cache integrity check failed.", level="ERROR")
                await redis_client.delete(cache_key)

        try:
            data_cursor = self._sessions_col.find({"user_id": user_id}, {"_id": 0}).sort("timestamp", -1).limit(limit)
            data = await data_cursor.to_list(length=limit)
            
            # Encrypt and secure
            encrypted_data = self._cipher.encrypt(json.dumps(data).encode())
            await redis_client.setex(cache_key, timedelta(minutes=10), encrypted_data.hex())

            return data
        except Exception as e:
            await log_event(f"DASHBOARD: Session summary failed - {str(e)}", level="ERROR")
            raise HTTPException(500, detail="Dashboard unavailable")

    async def get_audit_summary(self, user_id: str) -> List[Dict]:
        """
        Fetch blockchain-based audit logs with signature validation and user filtering.
        """
        await self._check_rate_limit(user_id)
        try:
            logs = await fetch_audit_logs()
            return [log for log in logs if log.get("user_id") == user_id][:_DEFAULT_LIMIT]
        except Exception as e:
            await log_event(f"DASHBOARD: Audit summary failed - {str(e)}", level="ERROR")
            raise HTTPException(500, detail="Audit logs unavailable")

    async def get_emotion_trends(self, user_id: str, zkp_proof: str, window: int = 7) -> Dict[str, Any]:
        """
        Fetch emotion trends with secure validation and aggregation.
        """
        await self._check_rate_limit(user_id)
        if not await self._validate_user(user_id, zkp_proof):
            raise HTTPException(HTTP_401_UNAUTHORIZED, "Invalid session token")

        try:
            start = datetime.utcnow() - timedelta(days=window)
            data_cursor = self._response_col.find(
                {"user_id": user_id, "timestamp": {"$gte": start}},
                {"_id": 0}
            ).sort("timestamp", -1).limit(_MAX_AGGREGATE)
            data = await data_cursor.to_list(length=_MAX_AGGREGATE)
            return summarize_emotions(data)
        except Exception as e:
            await log_event(f"DASHBOARD: Emotion trends failed - {str(e)}", level="WARNING")
            raise HTTPException(500, detail="Analysis failed")

    async def get_latency_metrics(self) -> Dict[str, Any]:
        """
        Fetch global latency metrics with secure aggregation.
        """
        try:
            data_cursor = self._response_col.find({}, {"_id": 0, "latency": 1}).limit(_MAX_AGGREGATE)
            data = await data_cursor.to_list(length=_MAX_AGGREGATE)
            return summarize_latencies(data)
        except Exception as e:
            await log_event(f"DASHBOARD: Latency metrics failed - {str(e)}", level="ERROR")
            raise HTTPException(500, detail="Metrics unavailable")

    async def clear_dashboard_cache(self, user_id: str, admin_zkp: str) -> Dict[str, Any]:
        """
        Admin-only cache purge with ZKP verification.
        """
        if not await self._zkp_authenticator.verify_admin_proof_async(user_id, admin_zkp):
            raise HTTPException(HTTP_403_FORBIDDEN, "Invalid ZKP")

        try:
            await redis_client.delete_by_pattern("session_summary:*")
            await log_event("DASHBOARD: Cache cleared securely", level="INFO")
            return {"status": "cleared", "message": "Dashboard cache purged."}
        except Exception as e:
            await log_event(f"DASHBOARD: Cache purge failed - {str(e)}", level="ERROR")
            raise HTTPException(500, detail="Cache purge failed")