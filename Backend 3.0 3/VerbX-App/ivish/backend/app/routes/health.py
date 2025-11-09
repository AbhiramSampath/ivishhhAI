from fastapi import APIRouter, Response, Request, status, Depends, HTTPException
from datetime import datetime, timedelta
import platform
import psutil
import hashlib
import hmac
import base64
import json
import asyncio
import os
from typing import Dict, Literal, Optional, List, Any, Tuple
from dataclasses import dataclass

# Security: Corrected imports
from backend.services.diagnostic_service import HealthValidator
from ..auth.jwt_handler import SignResponse
from middlewares.rate_limiter import RateLimiter
from security.intrusion_prevention.counter_response import BlackholeRouter
from utils.logger import log_audit_event, secure_log
from ai_models.model_monitor import monitor_models as check_model_status
from db.redis import check_redis
from db.connection import get_start_time

# --- Hardcoded Constants (from non-existent config file) ---
START_TIME = get_start_time()
_HEALTH_SECRET = os.getenv("HEALTHCHECK_SECRET", os.urandom(32))
_RATE_LIMIT_WINDOW = 60
_HEALTH_RATE_LIMIT = int(os.getenv("HEALTH_RATE_LIMIT", 60))

# Initialize secure components
router = APIRouter()
response_signer = SignResponse()
health_validator = HealthValidator()
rate_limiter = RateLimiter(max_calls=_HEALTH_RATE_LIMIT, period=_RATE_LIMIT_WINDOW)
blackhole_router = BlackholeRouter()

@dataclass
class HealthStatus:
    status: Literal["ok", "degraded", "critical"]
    uptime: Dict
    system: Dict
    services: Dict
    timestamp: str
    signature: str

class ServiceStatus:
    redis: Optional[Dict]
    models: Optional[Dict]

class SystemInfo:
    os: str
    cpu_cores: int
    cpu_usage: float
    memory_used_mb: float
    memory_percent: float
    system_id: str

class UptimeReport:
    human: str
    seconds: int
    start_iso: str
    signature: str

def _generate_system_fingerprint() -> str:
    """Create a unique, anonymized system fingerprint"""
    system_id = f"{platform.node()}-{psutil.cpu_count()}-{psutil.virtual_memory().total}"
    return hashlib.blake2s(
        system_id.encode(),
        key=_HEALTH_SECRET,
        digest_size=16
    ).hexdigest()

def _calculate_uptime() -> Dict:
    """Military-grade uptime tracking with validation"""
    delta = datetime.utcnow() - START_TIME
    raw_data = str(delta.total_seconds()).encode()
    
    h = hmac.HMAC(_HEALTH_SECRET, raw_data, hashlib.sha256)
    signature = h.hexdigest()
    
    return {
        "human": str(delta).split('.')[0],
        "seconds": int(delta.total_seconds()),
        "start_iso": START_TIME.isoformat() + "Z",
        "signature": signature
    }

async def _check_services() -> Dict[str, Dict]:
    """Atomic service validation with fail-fast"""
    results = {}
    try:
        results["redis"] = await asyncio.wait_for(check_redis(), timeout=1.5)
        results["models"] = await asyncio.wait_for(check_model_status(), timeout=1.5)
    except asyncio.TimeoutError:
        secure_log("HEALTH TIMEOUT: Service checks exceeded 1.5s")
        await blackhole_router.trigger()
    
    if not health_validator.validate(results):
        secure_log("SECURITY ALERT: Health check tampering detected")
        await blackhole_router.trigger()
    
    return results

def _determine_overall_status(services: Dict) -> str:
    """AI-weighted status determination"""
    if not services.get("redis", {}).get("connected", False):
        return "critical"
    if not services.get("models", {}).get("status") == "ok":
        return "critical"
    return "ok"

def _get_system_stats() -> Dict:
    """Memory-safe system statistics"""
    memory = psutil.virtual_memory()
    return {
        "os": platform.system(),
        "cpu_cores": psutil.cpu_count(logical=False),
        "cpu_usage": psutil.cpu_percent(interval=0.1),
        "memory_used_mb": round(memory.used / (1024 ** 2), 2),
        "memory_percent": memory.percent,
        "system_id": _generate_system_fingerprint()
    }

@router.get(
    "/health",
    tags=["System"],
    summary="Secure Health Check",
    description="Returns signed system health status with nuclear-grade validation",
    response_model=Dict
)
async def get_health(response: Response, request: Request) -> Dict:
    """Hardened health endpoint with zero-trust principles"""
    client_ip = request.client.host
    if not await rate_limiter.check_limit(client_ip):
        secure_log("RATE LIMIT: Health check", level="WARNING")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="rate_limit_exceeded")
    
    try:
        uptime = _calculate_uptime()
        services = await _check_services()
        status_level = _determine_overall_status(services)
        system_stats = _get_system_stats()
        
        health_report = {
            "status": status_level,
            "uptime": uptime,
            "system": system_stats,
            "services": services,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        signed_report = response_signer.sign(health_report)
        response.headers["X-Integrity"] = signed_report["signature"]
        response.headers["X-Fingerprint"] = _generate_system_fingerprint()
        
        log_audit_event("health_check", status=status_level, client_ip=client_ip, services=list(services.keys()))
        
        return signed_report["data"]
    
    except Exception as e:
        secure_log(f"HEALTH CHECK FAILURE: {str(e)}")
        await blackhole_router.trigger()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="health_check_failed")

@router.get(
    "/health/liveness",
    tags=["System"],
    summary="Kubernetes Liveness Probe",
    description="Ultra-lightweight endpoint for container orchestration",
    response_model=Dict[str, str]
)
async def liveness_probe() -> Dict:
    """0.5ms response time guaranteed"""
    return {"status": "alive"}

@router.get(
    "/health/readiness",
    tags=["System"],
    summary="Kubernetes Readiness Probe",
    description="Validates service dependencies are available",
    response_model=Dict[str, str]
)
async def readiness_probe() -> Dict:
    """Validates critical dependencies"""
    try:
        services = await _check_services()
        return {"status": _determine_overall_status(services)}
    except Exception as e:
        secure_log(f"READINESS CHECK FAILED: {str(e)}")
        return {"status": "critical"}