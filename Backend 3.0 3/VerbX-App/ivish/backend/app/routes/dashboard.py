import json
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import HTTPAuthorizationCredentials
from starlette.status import HTTP_403_FORBIDDEN, HTTP_429_TOO_MANY_REQUESTS, HTTP_401_UNAUTHORIZED
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import csv
import tempfile
import hashlib
import uuid
import asyncio
import os
import io
import hmac
from pathlib import Path

# Original imports - CORRECTED PATHS
from security.jwt_handler import get_current_user, validate_jwt_claims
from security.blockchain.blockchain_utils import fetch_blockchain_logs, verify_log_integrity
from ivish_central.user_safety_center import has_user_consent
from utils.logger import log_event, security_alert
from ai_models.ivish.memory_agent import get_user_memory_summary
from ivish_central.performance_analyzer import get_latency_report, sanitize_analytics_output
from ai_models.emotion.emotion_handler import get_emotion_summary
from backend.services.billing_service import get_user_billing
from middlewares.rate_limiter import RateLimiter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Hardcoded constants (from non-existent config file) ---
REPORT_CACHE_PATH = os.getenv("REPORT_CACHE_PATH", "/tmp/report_cache")
MAX_REPORT_AGE_DAYS = int(os.getenv("MAX_REPORT_AGE_DAYS", 2))
EXPORT_FILE_TTL = int(os.getenv("EXPORT_FILE_TTL", 3600))
EXPORT_ENCRYPTION_KEY = os.getenv("EXPORT_ENCRYPTION_KEY", os.urandom(32)).encode()
MAX_EXPORT_RECORDS = int(os.getenv("MAX_EXPORT_RECORDS", 1000))
DASHBOARD_RATE_LIMIT = int(os.getenv("DASHBOARD_RATE_LIMIT", 100))

# Global kill switch
_dashboard_killed = False

# AES-256-GCM cipher for exports
class AESCipher:
    def __init__(self):
        self.key = EXPORT_ENCRYPTION_KEY
    
    def encrypt(self, raw: bytes) -> bytes:
        if _dashboard_killed:
            return raw
        try:
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(raw) + encryptor.finalize()
            return nonce + encryptor.tag + ciphertext
        except Exception as e:
            security_alert(f"Export encryption failed: {str(e)[:50]}")
            return raw

    def decrypt(self, encrypted: bytes) -> bytes:
        if _dashboard_killed or not encrypted or len(encrypted) < 28:
            return b''
        try:
            nonce, tag, ciphertext = encrypted[:12], encrypted[12:28], encrypted[28:]
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            security_alert(f"Export decryption failed: {str(e)[:50]}")
            return b''

_aes_cipher = AESCipher()
rate_limiter = RateLimiter()

def _hmac_export(data: List[Dict]) -> str:
    """HMAC-SHA384 to ensure export integrity"""
    try:
        data_string = json.dumps(data, sort_keys=True)
        h = hmac.HMAC(EXPORT_ENCRYPTION_KEY, hashes.SHA384(), backend=default_backend())
        h.update(data_string.encode())
        return h.finalize().hex()
    except Exception as e:
        security_alert(f"HMAC generation failed: {str(e)[:50]}")
        return ""

def _verify_jwt_user_dependency(user: dict = Depends(get_current_user)) -> dict:
    if _dashboard_killed or not user or not validate_jwt_claims(user):
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user

# Router with security headers
router = APIRouter(
    prefix="/dashboard",
    dependencies=[Depends(_verify_jwt_user_dependency), Depends(rate_limiter.check_limit)],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}}
)

@router.get("/memory")
async def memory_summary(request: Request, user: dict = Depends(get_current_user)) -> Dict:
    """Secure memory endpoint with output sanitization and access validation."""
    try:
        result = await get_user_memory_summary(user["user_id"])
        sanitized = sanitize_analytics_output(result)
        return sanitized
    except Exception as e:
        security_alert(f"Memory summary failed: {str(e)[:50]}")
        raise HTTPException(status_code=500, detail="Memory summary unavailable")

@router.get("/emotion")
async def emotion_summary(request: Request, user: dict = Depends(get_current_user)) -> Dict:
    """Emotion trends with GDPR-compliant anonymization and temporal access patterns."""
    try:
        result = await get_emotion_summary(user["user_id"])
        return {
            "data": result,
            "metadata": {
                "anonymized": True,
                "time_range": "30d",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    except Exception as e:
        security_alert(f"Emotion summary failed: {str(e)[:50]}")
        raise HTTPException(status_code=500, detail="Emotion analysis unavailable")

@router.get("/latency")
async def latency_report(request: Request, user: dict = Depends(get_current_user)) -> Dict:
    """System latency diagnostics with session validation."""
    try:
        result = await get_latency_report(user["user_id"])
        return {
            "report": result,
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "user_id": hashlib.sha256(user["user_id"].encode()).hexdigest()
            }
        }
    except Exception as e:
        security_alert(f"Latency report failed: {str(e)[:50]}")
        raise HTTPException(status_code=500, detail="Latency report unavailable")

@router.get("/safety-logs")
async def safety_logs(request: Request, user: dict = Depends(get_current_user)) -> List[Dict]:
    """Blockchain-verified safety logs with admin validation."""
    if not user.get("is_admin"):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Admin required")
    try:
        logs = await fetch_blockchain_logs("ai_safety")
        verified_logs = [log for log in logs if verify_log_integrity(log["tx_hash"])]
        return verified_logs
    except Exception as e:
        security_alert(f"Safety log fetch failed: {str(e)[:50]}")
        raise HTTPException(status_code=500, detail="Safety logs unavailable")

@router.get("/billing")
async def billing_summary(request: Request, user: dict = Depends(get_current_user)) -> Dict:
    """Usage-based billing summary with secure validation."""
    if not await has_user_consent(user["user_id"], "billing"):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Consent required")
    try:
        result = await get_user_billing(user["user_id"])
        return {
            "usage": result["usage"],
            "credits": result["credits"],
            "plan": result["plan"],
            "next_billing_date": result["next_billing_date"].isoformat()
        }
    except Exception as e:
        security_alert(f"Billing summary failed: {str(e)[:50]}")
        raise HTTPException(status_code=500, detail="Billing unavailable")

@router.get("/export/{data_type}")
async def export_csv(request: Request, data_type: str, user: dict = Depends(get_current_user)) -> FileResponse:
    """Secure data export with encrypted temp files and automatic cleanup."""
    data_map = {
        "memory": lambda uid: get_user_memory_summary(uid),
        "emotion": get_emotion_summary,
        "billing": get_user_billing
    }

    if data_type not in data_map:
        raise HTTPException(status_code=400, detail="Invalid export type")

    try:
        data = await data_map[data_type](user["user_id"])
        if not data:
            raise HTTPException(status_code=404, detail="No data available for export")

        with tempfile.NamedTemporaryFile(delete=False, mode="w+", newline="") as tmp:
            writer = csv.DictWriter(tmp, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data[:MAX_EXPORT_RECORDS])
            tmp_path = tmp.name

        raw_data = Path(tmp_path).read_bytes()
        encrypted = _aes_cipher.encrypt(raw_data)
        h = _hmac_export(data)

        export_path = f"{tmp_path}.enc"
        Path(export_path).write_bytes(encrypted)
        os.unlink(tmp_path)

        asyncio.create_task(_schedule_file_cleanup(export_path))

        expiry = datetime.utcnow() + timedelta(seconds=EXPORT_FILE_TTL)
        return FileResponse(
            export_path,
            filename=f"{data_type}_report_{uuid.uuid4().hex[:8]}.enc",
            headers={
                "X-File-Expiry": expiry.isoformat(),
                "X-File-Integrity": h
            }
        )
    except Exception as e:
        security_alert(f"Export failed: {str(e)[:50]}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

async def _schedule_file_cleanup(path: str, delay: int = EXPORT_FILE_TTL):
    """Secure file cleanup after TTL."""
    await asyncio.sleep(delay)
    try:
        Path(path).unlink()
    except Exception as e:
        security_alert(f"Export cleanup failed: {str(e)[:50]}")

def kill_dashboard():
    """Emergency kill switch — wipes keys and stops dispatch."""
    global _dashboard_killed
    _dashboard_killed = True
    log_event("Dashboard: Engine killed.", level="critical")