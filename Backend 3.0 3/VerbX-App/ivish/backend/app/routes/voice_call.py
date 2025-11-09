# voice call/handler.py

import os
import time
import json
import uuid
import asyncio
import hashlib
import hmac
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any
from collections import defaultdict
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import APIKeyHeader

# SECURITY: Corrected imports
from utils.logger import log_event
from security.voice_biometric_auth import validate_voice_session
from voice_call.translator import handle_bilingual_call
from backend.app.services.permission_service import check_permission as check_call_permission
from middlewares.rate_limiter import RateLimiter as VoiceStreamRateLimiter
from security.intrusion_prevention.counter_response import BlackholeRouter
from utils.helpers import apply_differential_privacy

# LOGGER CONFIG
logger = logging.getLogger(__name__)

# SECURITY CONSTANTS - Defined locally as config file is not in PDF
HMAC_KEY = os.getenv("VOICE_CALL_HMAC_KEY", os.urandom(32)).encode()
MAX_CALL_DURATION = int(os.getenv("MAX_CALL_DURATION", "3600"))
MAX_STREAM_ATTEMPTS = int(os.getenv("VOICE_STREAM_RATE_LIMIT", "10"))
RATE_LIMIT_WINDOW = int(os.getenv("VOICE_CALL_RATE_LIMIT_WINDOW", "60"))
MIN_PROCESSING_TIME_MS = int(os.getenv("VOICE_CALL_MIN_PROCESSING_TIME", "100"))

# Initialize router
router = APIRouter(
    prefix="/ws/call",
    tags=["Voice Call"],
    dependencies=[Depends(APIKeyHeader(name="X-API-Key"))]
)

class SecureCallManager:
    def __init__(self):
        self._active_calls = {}
        self._rate_limiter = VoiceStreamRateLimiter(max_calls=MAX_STREAM_ATTEMPTS, period=RATE_LIMIT_WINDOW)
        self._blackhole = BlackholeRouter()

    def _generate_call_token(self, user_id: str, target_id: str) -> str:
        try:
            h = hmac.new(HMAC_KEY, digestmod=hashlib.sha256)
            h.update(f"{user_id}{target_id}{uuid.uuid4()}".encode())
            token = h.hexdigest()
            return token
        except Exception as e:
            logger.warning("Call token generation failed", exc_info=True)
            return ""

    async def _validate_websocket(self, ws: WebSocket) -> bool:
        try:
            origin = ws.headers.get("origin", "")
            if origin not in ["https://yourdomain.com", "wss://yourdomain.com"]:
                return False
            return True
        except Exception as e:
            logger.warning("WebSocket validation failed", exc_info=True)
            return False

    async def _apply_processing_delay(self, start_time: float, target_ms: int):
        elapsed_ms = (time.time() - start_time) * 1000
        if elapsed_ms < target_ms:
            await asyncio.sleep((target_ms - elapsed_ms) / 1000)

    async def _fail_safe_response(self) -> Dict:
        return {"status": "error", "reason": "Call service unavailable"}

call_manager = SecureCallManager()

@router.websocket("/{user_id}/{target_id}")
async def initiate_call(ws: WebSocket, user_id: str, target_id: str):
    start_time = time.time()
    try:
        if not await call_manager._validate_websocket(ws):
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await ws.accept()

        if not user_id or not target_id or user_id == target_id:
            await ws.send_json({"error": "invalid_call", "code": 400})
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        if not await check_call_permission(user_id, target_id):
            await ws.send_json({"error": "call_denied", "code": 403})
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            log_event("Call permission denied", user=user_id, target=target_id, level="WARNING")
            return

        session_id = call_manager._generate_call_token(user_id, target_id)
        if not session_id:
            await ws.send_json({"error": "call_registration_failed", "code": 500})
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await call_manager._apply_processing_delay(start_time, target_ms=MIN_PROCESSING_TIME_MS)

        try:
            await handle_bilingual_call(ws, user_id, target_id, session_id)
        finally:
            await log_event("Call terminated", user=user_id, target=target_id)

    except WebSocketDisconnect as e:
        log_event(f"Call disconnected", user=user_id, target=target_id, code=e.code)
    except Exception as e:
        logger.warning("Call initiation failed", exc_info=True)
        await ws.send_json({"error": "call_initiation_failed", "code": 500})

def _connect_target_user(target_id: str) -> Optional[WebSocket]:
    logger.debug(f"Connecting to target user {target_id}")
    return None

async def _handle_call_with_timeout(
    ws: WebSocket,
    user_id: str,
    target_id: str,
    session_id: str
):
    try:
        ws_target = _connect_target_user(target_id)
        if not ws_target:
            await ws.send_json({"error": "target_unavailable", "code": 503})
            return
        await asyncio.wait_for(
            handle_bilingual_call(ws, ws_target, session_id),
            timeout=MAX_CALL_DURATION
        )
    except asyncio.TimeoutError:
        await ws.send_json({"warning": "call_timeout"})
        log_event("Call duration limit reached", session=session_id)
    except ConnectionError as e:
        await ws.send_json({"error": "stream_failure"})
        log_event("Stream connection failed", error=str(e), level="ERROR")
    except Exception as e:
        logger.warning("Call handling failed", exc_info=True)
        await ws.send_json({"error": "call_failed", "code": 500})

async def _secure_call_teardown(
    user_id: str,
    target_id: str,
    session_id: str
):
    try:
        log_data = apply_differential_privacy({
            "user_id": user_id,
            "target_id": target_id,
        }, epsilon=0.1)

        log_event("Call terminated", user=user_id, target=target_id, meta=log_data)
        # End call in session tracker
        await end_call(user_id, target_id)
    except Exception as e:
        logger.warning("Call teardown failed", exc_info=True)