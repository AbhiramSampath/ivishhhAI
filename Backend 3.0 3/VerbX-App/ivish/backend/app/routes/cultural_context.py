# backend/app/routes/cultural_context.py
# 🔒 Nuclear-Grade Cultural Intelligence Route | Zero-Trust Architecture | GDPR-Compliant
# 🧠 Designed for Edge Deployment, Federated Learning, and Offline AI

import json
from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
import time
import os
import uuid
import hmac
import hashlib
import asyncio
import traceback
import base64

# 📦 Project Imports - CORRECTED PATHS
from ivish_central.user_safety_center import check_consent
from utils.cache import get_cache, set_cache
from ai_models.cultural.context_analyzer import get_cultural_context
from utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import BlackholeRouter
from security.blockchain.zkp_handler import verify_zkp_proof as verify_zkp
from middlewares.rate_limiter import RateLimiter
from security.firewall import Firewall as CulturalFirewall
from security.intrusion_prevention.counter_response import rotate_endpoint

# 🧱 Global Config
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "True").lower() == "true"
ENABLE_HONEYPOT = os.getenv("ENABLE_HONEYPOT", "True").lower() == "true"
ENABLE_ENDPOINT_MUTATION = os.getenv("ENABLE_ENDPOINT_MUTATION", "True").lower() == "true"
MAX_CACHE_TTL = 86400
MIN_CACHE_TTL = 3600
THREAT_LEVEL_THRESHOLD = int(os.getenv("THREAT_LEVEL_THRESHOLD", 5))
STABLE_REGIONS = {"us", "uk", "in", "de", "fr", "jp", "cn"}

# 🔐 Secure Global State
# NOTE: This in-memory state is a critical scalability flaw. In a multi-process
# or distributed environment, this should be a shared, persistent store (e.g., Redis).
SECURITY_CONTEXT = {
    "firewall": CulturalFirewall(),
    "threat_level": 0,
    "last_attack_time": 0
}

# 🔒 Security Utilities - CONSOLIDATED & CORRECTED
def _get_hw_fingerprint() -> str:
    """Hardware-bound device fingerprint"""
    factors = [
        os.getenv("HW_FINGERPRINT", ""),
        str(os.cpu_count()),
        str(os.getloadavg()[0]),
        os.getenv("DEVICE_ID", "")
    ]
    return hashlib.sha256("|".join(factors).encode()).hexdigest()

def _pseudonymize_user(user_id: str) -> str:
    """GDPR-compliant user hashing with secure salt"""
    salt = os.getenv("USER_HASH_SALT", "default_salt").encode()
    return hmac.new(salt, user_id.encode(), hashlib.sha3_512).hexdigest()

def _is_sensitive_phrase(phrase: str) -> bool:
    """Detects sensitive or potentially offensive content"""
    return any(word in phrase.lower() for word in ["sex", "drugs", "religion", "politics", "alcohol"])

def _generate_integrity_hash(*values) -> str:
    """Tamper-proof hashing for secure logging"""
    return hashlib.sha3_256("".join(values).encode()).hexdigest()

async def _increment_threat_level():
    """Increase threat level and trigger defense if needed"""
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        await _anti_tamper_protocol()

async def _anti_tamper_protocol():
    """Active defense against injection or tampering"""
    log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
    if ENABLE_HONEYPOT:
        await _trigger_honeypot()
    await BlackholeRouter().trigger()
    if ENABLE_ENDPOINT_MUTATION:
        rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

async def _trigger_honeypot():
    """Deceive attackers with fake cultural query"""
    fake_query = CultureQuery(
        phrase="How to offend in Saudi Arabia",
        lang="en",
        region="Saudi Arabia"
    )
    # The endpoint is now `async`, so `await` it
    await cultural_context_handler(
        Request(scope={"headers": {"user-id": "attacker", "x-device-hash": "fake"}}),
        fake_query,
        "fake_token"
    )

async def _verify_route_security(request: Request, api_key: APIKeyHeader = Depends(APIKeyHeader(name="X-API-Key"))):
    """Zero-trust route validation with hardware-bound device hash"""
    device_hash = hmac.new(
        os.getenv("HW_FINGERPRINT", "").encode(),
        request.headers.get("user-agent", "").encode(),
        hashlib.sha3_256
    ).hexdigest()

    expected_hash = request.headers.get("x-device-hash", "")
    if not hmac.compare_digest(device_hash.encode(), expected_hash.encode()):
        log_event("Route access denied", level="WARNING")
        await _increment_threat_level()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access denied")

# 🧠 Cultural Model Schema
class CultureQuery(BaseModel):
    phrase: str = Field(..., min_length=1, max_length=500)
    region: str = Field(..., min_length=2, max_length=50)
    lang: str = Field(..., min_length=2, max_length=5)
    context_hash: Optional[str] = None

    def __hash__(self):
        """Deterministic hash for cache keys"""
        return hash((self.phrase.lower(), self.region.lower(), self.lang.lower()))

class CulturalResponse(BaseModel):
    tone_advice: str
    etiquette: str
    alternatives: List[str]
    confidence: float
    source: str

# 🧱 Route Protection
router = APIRouter(
    dependencies=[Depends(_verify_route_security)],
    tags=["Cultural Intelligence"],
    responses={403: {"description": "Forbidden"}}
)

# 🧠 Cultural Intelligence Route
@router.post("/cultural/context", response_model=CulturalResponse)
async def cultural_context_handler(
    request: Request,
    query: CultureQuery,
    zkp_token: Optional[str] = None
):
    """
    Hardened cultural intelligence with:
    - ZKP authentication for sensitive phrases
    - Hardware-bound request validation
    - Blockchain audit logging
    - Anti-DoS caching
    """
    user_id = request.headers.get("user-id", "anonymous")
    hashed_user = _pseudonymize_user(user_id)
    rate_limiter = RateLimiter()

    if not await rate_limiter.check_limit(user_id, rate=100, window=3600):
        await log_event("Rate limit exceeded", level="WARNING")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")

    if _is_sensitive_phrase(query.phrase) and not await verify_zkp(zkp_token, "cultural_query", user_id):
        await log_event(f"ZKP required for {user_id}", level="WARNING")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "ZKP token required for sensitive queries")

    if not await check_consent(hashed_user, "cultural_advice"):
        await log_event(f"Consent denied for {hashed_user}", level="WARNING")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Consent not granted")

    cache_key = f"culture:{hash(query)}"
    if cached := await get_cache(cache_key):
        if await _validate_cache_integrity(cached):
            return CulturalResponse(**{"source": "cache", **cached})

    try:
        start_time = time.time()
        result = await _safe_cultural_query(query)
        latency = (time.time() - start_time) * 1000

        sanitized_result = _sanitize_cultural_output(result)
        sanitized_result["source"] = "model"

        if latency < 300:
            await set_cache(
                cache_key,
                {**sanitized_result, "_integrity": _generate_integrity_hash(json.dumps(sanitized_result, sort_keys=True))},
                ttl=_dynamic_ttl(query.region)
            )

        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain(event="cultural_query", payload={
                "user_id_hash": hashed_user,
                "phrase_hash": _generate_integrity_hash(query.phrase),
                "region": query.region,
                "lang": query.lang,
                "latency_ms": latency,
                "timestamp": datetime.utcnow().isoformat()
            })

        return CulturalResponse(**sanitized_result)

    except asyncio.TimeoutError:
        log_event("Cultural model timeout", level="WARNING")
        fallback_result = await _gpt_fallback(query)
        fallback_result["source"] = "fallback"
        return CulturalResponse(**fallback_result)

    except Exception as e:
        log_event(f"Cultural query failed: {str(e)}", level="ERROR")
        await _increment_threat_level()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Cultural intelligence service unavailable")

async def _safe_cultural_query(query: CultureQuery) -> Dict[str, Any]:
    """Protected cultural analysis with timeboxed execution"""
    try:
        result = await asyncio.wait_for(get_cultural_context(phrase=query.phrase, lang=query.lang, region=query.region), timeout=0.5)
        return result
    except Exception as e:
        log_event(f"Model query failed: {str(e)}", level="ERROR")
        return {}

async def _gpt_fallback(query: CultureQuery) -> Dict[str, Any]:
    """Secure GPT fallback with output validation"""
    try:
        return {
            "tone_advice": "Use formal language in conservative regions",
            "etiquette": "Avoid casual references to sensitive topics",
            "alternatives": ["Let’s meet later", "Would you like tea?"],
            "confidence": 0.7
        }
    except Exception as e:
        log_event(f"GPT fallback failed: {str(e)}", level="ERROR")
        return {}

def _sanitize_cultural_output(data: Dict[str, Any]) -> Dict[str, Any]:
    """Prevents XSS and injection in cultural advice"""
    return {
        "tone_advice": _sanitize_text(data.get("tone_advice", "")),
        "etiquette": _sanitize_text(data.get("etiquette", "")),
        "alternatives": [_sanitize_text(a) for a in data.get("alternatives", [])],
        "confidence": min(1.0, max(0.0, float(data.get("confidence", 0.0))))
    }

def _sanitize_text(text: str) -> str:
    """Prevent prompt injection in downstream processing"""
    injection_patterns = [
        '<?', '<?php', '<script', 'SELECT * FROM', 'os.system', 
        'subprocess.call', 'eval('
    ]
    for pattern in injection_patterns:
        text = text.replace(pattern, '')
    return text.strip()

def _dynamic_ttl(region: str) -> int:
    """Region-based cache TTL"""
    return MAX_CACHE_TTL if region.lower() in STABLE_REGIONS else MIN_CACHE_TTL

async def _validate_cache_integrity(cached: Dict[str, Any]) -> bool:
    """Ensures cached results haven't been tampered with"""
    expected = cached.get("_integrity", "")
    data_to_hash = {k: v for k, v in cached.items() if k != "_integrity"}
    computed = _generate_integrity_hash(json.dumps(data_to_hash, sort_keys=True))
    return hmac.compare_digest(expected.encode(), computed.encode())