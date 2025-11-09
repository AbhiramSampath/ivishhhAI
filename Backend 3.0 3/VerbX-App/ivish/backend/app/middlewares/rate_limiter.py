# backend/middleware/rate_limiter.py

import time
import asyncio
import logging
import hashlib
import hmac
import secrets
import json
import os
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from collections import defaultdict
from datetime import datetime, timedelta
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.status import HTTP_429_TOO_MANY_REQUESTS, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
from starlette.types import ASGIApp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Project Imports - CORRECTED PATHS
from security.blockchain.blockchain_utils import log_to_blockchain
from utils.logger import log_event
from security.jwt_handler import get_user_id_from_token
from db.redis import increment_request_count, get_request_count
from security.zkp_handler import ZeroKnowledgeProof
# from ..ai_models.ivish.memory_agent import MemorySessionHandler  # Stubbed
# from ..security.intrusion_prevention.counter_response import BlackholeRouter  # Stubbed

class MemorySessionHandler:
    pass

class BlackholeRouter:
    pass

# Stub for decrypt_env_var to fix import error
def decrypt_env_var(value: str) -> str:
    return value

# Security Constants - Defined locally as config file is not in PDF
_MINIMUM_TTL_SEC = 60
_HKDF_SALT = b"IvishRateLimitv2"
_HMAC_KEY = os.getenv("RATE_HMAC_KEY", "default_rate_key").encode()
_BLACKHOLE_THRESHOLD = 5
_DEFAULT_MAX_VIOLATIONS = 10
_RATE_LOG_TTL = 60 * 60 * 24
_RATE_LOG_TYPE = "rate_abuse"
_RATE_LIMITS = {
    "/chat": (100, 60), "/translate": (50, 60), "/tts": (50, 60),
    "/stt": (60, 60), "/api/emoji": (200, 60)
}
_WHITELISTED_ROUTES = {"/health", "/health/liveness", "/health/readiness"}
_AI_RATE_ADAPTIVE = os.getenv("AI_RATE_ADAPTIVE", "False").lower() == "true"

# Initialize secure components
logger = logging.getLogger(__name__)
memory_handler = MemorySessionHandler()
blackhole_router = BlackholeRouter()
backend = default_backend()
hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=b"rate_limiter", backend=backend)

class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.config = self._load_config()
        self.defense = self._init_defense()
        
    def _load_config(self):
        return {
            "limits": _RATE_LIMITS,
            "whitelisted": _WHITELISTED_ROUTES,
            "ai_adaptive": _AI_RATE_ADAPTIVE
        }

    def _init_defense(self):
        return {
            "blacklist": defaultdict(int),
            "honeypot_routes": {},
            "threat_level": 0
        }

    async def dispatch(self, request: Request, call_next) -> Response:
        route = request.url.path
        method = request.method

        if method == "OPTIONS" or self.config["whitelisted"].get(route):
            return await call_next(request)

        user_token = request.headers.get("Authorization", "")
        ip = request.client.host if request.client else "0.0.0.0"

        try:
            user_id = await get_user_id_from_token(user_token)
        except Exception:
            user_id = ip

        log_event(f"RATE: Processing request from {user_id} ({ip}) to {route} ({method})", level="INFO")

        if self.defense["blacklist"].get(user_id, 0) >= _BLACKHOLE_THRESHOLD:
            return await self._blackhole_response(request, user_id, route, ip)

        max_limit, ttl = await self._get_limits(route, user_id)
        key = self._get_bucket_id(user_id, route, request)
        req_count = await increment_request_count(key, ttl)

        if req_count > max_limit:
            return await self._handle_violation(user_id, route, request, req_count, ip)

        response = await call_next(request)
        response.headers.update({
            "X-RateLimit-Limit": str(max_limit),
            "X-RateLimit-Remaining": str(max(max_limit - req_count, 0)),
            "X-RateLimit-Reset": str(int(time.time() + ttl))
        })
        return response

    async def _get_limits(self, route: str, user_id: str) -> Tuple[int, int]:
        base_limit, ttl = self.config["limits"].get(route, (30, _MINIMUM_TTL_SEC))
        if not self.config["ai_adaptive"]:
            return base_limit, ttl
        
        from ai_models.usage_predictor import load_usage_model
        model = await load_usage_model()
        try:
            factor = await model.predict(user_id, route)
            return int(base_limit * factor), max(ttl, _MINIMUM_TTL_SEC)
        except Exception as e:
            log_event(f"RATE: AI prediction failed - {str(e)}", level="WARNING")
            return base_limit, ttl

    def _get_bucket_id(self, user_id: str, route: str, request: Request) -> str:
        fingerprint = f"{user_id}:{route}:{request.client.host}:{request.headers.get('User-Agent', '')}"
        derived_key = hkdf.derive(fingerprint.encode())
        return f"rate:{derived_key.hex()}:{int(time.time() // 60)}"

    async def _handle_violation(self, user_id: str, route: str, request: Request, count: int, ip: str) -> JSONResponse:
        await log_to_blockchain("rate_abuse", {
            "user_id": user_id, "route": route, "count": count, "ip": ip,
            "ua": request.headers.get("User-Agent"), "timestamp": datetime.utcnow().isoformat()
        })
        violation_key = f"violation:{user_id}"
        violations = await increment_request_count(violation_key, 86400)
        if violations >= _DEFAULT_MAX_VIOLATIONS:
            await self._trigger_blackhole(user_id, ip)
        log_event(f"RATE: ⚠️ Violation by {user_id} ({ip}) on {route} ({count} requests, UA: {request.headers.get('User-Agent', 'unknown')})", level="WARNING")
        return JSONResponse(status_code=HTTP_429_TOO_MANY_REQUESTS, headers={"Retry-After": str(_MINIMUM_TTL_SEC)}, content={"detail": "Rate limit exceeded", "retry_after": _MINIMUM_TTL_SEC})

    async def _blackhole_response(self, request: Request, user_id: str, route: str, ip: str) -> JSONResponse:
        log_event(f"RATE: Blackhole response activated for {user_id} ({ip}) on {route}", level="SECURE")
        await asyncio.sleep(30)
        return JSONResponse(status_code=HTTP_404_NOT_FOUND, content={"detail": "Resource not found"})

    async def _trigger_blackhole(self, user_id: str):
        self.defense["blacklist"][user_id] = self.defense["blacklist"].get(user_id, 0) + 1
        if self.defense["blacklist"][user_id] >= _BLACKHOLE_THRESHOLD:
            log_event(f"RATE: User {user_id} blacklisted for abuse", level="CRITICAL")
            await blackhole_router.trigger(ip_address=user_id)

    async def _check_zkp(self, request: Request) -> bool:
        zkp_token = request.headers.get("X-ZKP-Token")
        if not zkp_token: return False
        return ZeroKnowledgeProof().verify(zkp_token, request.url.path.encode())

    async def _check_trusted_device(self, request: Request) -> bool:
        device_hash = hashlib.sha256(request.headers.get("User-Agent", "").encode()).hexdigest()
        trusted_devices = await memory_handler.get_trusted_devices(get_user_id_from_token(request.headers.get("Authorization")))
        return device_hash in trusted_devices

    async def _check_ai_bypass(self, request: Request) -> bool:
        if not self.config["ai_adaptive"]: return False
        try:
            usage_pattern = await memory_handler.get_usage_pattern(get_user_id_from_token(request.headers.get("Authorization")))
            return usage_pattern.get("is_trusted", False)
        except Exception as e:
            log_event(f"RATE: AI bypass check failed - {str(e)}", level="ERROR"); return False

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)

    async def check_limit(self, user_id: str) -> bool:
        now = time.time()
        self.requests[user_id] = [t for t in self.requests[user_id] if now - t < 60]
        if len(self.requests[user_id]) >= 30:
            return False
        self.requests[user_id].append(now)
        return True
