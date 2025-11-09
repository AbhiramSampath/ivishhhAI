# backend/middleware/request_logger.py

import os
import time
import uuid
import asyncio
import hashlib
import hmac
import logging
import json
import re
from datetime import datetime
from typing import Dict, Any, Optional, Union
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.datastructures import Headers

# SECURITY: Corrected imports
from utils.logger import log_event
from security.security import redact_sensitive
from security.blockchain.blockchain_utils import log_to_blockchain
from middlewares.rate_limiter import RateLimiter
from security.encryption_utils import AES256Cipher
from utils.helpers import apply_differential_privacy

# LOGGER CONFIG
logger = logging.getLogger(__name__)

# CONSTANTS
MAX_BODY_SIZE = int(os.getenv("REQUEST_LOGGER_MAX_BODY_SIZE", "4096"))
REDACT_FIELDS = os.getenv("SENSITIVE_FIELDS", "password,token,secret,credit_card").split(",")
HMAC_KEY = os.getenv("REQUEST_LOGGER_HMAC_KEY", os.urandom(32)).encode()
MIN_PROCESSING_TIME_MS = int(os.getenv("REQUEST_LOGGER_MIN_DELAY", "2"))
RATE_LIMIT = int(os.getenv("REQUEST_LOGGER_RATE_LIMIT", "1000"))

class SecureRequestLogger(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.logger = logging.getLogger(__name__)
        self.rate_limiter = RateLimiter()
        self._cipher = AES256Cipher()
        self._rate_limit_window = 1

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        start_time = time.monotonic()
        client_ip = self._extract_client_ip(request)

        if not await self.rate_limiter.check_limit(client_ip, rate=RATE_LIMIT, window=self._rate_limit_window):
            return Response("Too Many Requests", status_code=429)

        try:
            body = await self._safe_read_body(request)
            log_data = await self._create_log_entry(request_id, request, body, client_ip)
            asyncio.create_task(self._emit_logs_async(log_data))

            response = await call_next(request)

            duration = time.monotonic() - start_time
            asyncio.create_task(self._log_response_async(request_id, str(request.url.path), response.status_code, duration, dict(response.headers)))

            return response
        except Exception as e:
            log_event(f"[CRITICAL] Request {request_id} failed", level="ALERT", meta={"path": str(request.url.path), "error_type": type(e).__name__})
            await asyncio.sleep(max(0, (MIN_PROCESSING_TIME_MS - (time.monotonic() - start_time) * 1000) / 1000))
            raise

    def _extract_client_ip(self, request: Request) -> str:
        x_forwarded_for = request.headers.get("x-forwarded-for", "")
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(",")[0].strip()
        else:
            client_ip = str(request.client.host)
        return apply_differential_privacy({"ip": client_ip}, epsilon=0.01)["ip"]

    async def _safe_read_body(self, request: Request) -> str:
        try:
            body = await request.body()
            if len(body) > MAX_BODY_SIZE:
                return f"<truncated {len(body)} bytes>"
            return redact_sensitive(body.decode("utf-8", errors="replace"), REDACT_FIELDS)
        except Exception as e:
            self.logger.warning("Body reading failed", exc_info=True)
            return "<binary>"

    async def _create_log_entry(self, request_id: str, request: Request, body: str, client_ip: str) -> Dict[str, Any]:
        timestamp = datetime.utcnow().isoformat() + "Z"
        entry = {
            "request_id": request_id, "timestamp": timestamp, "method": request.method,
            "path": str(request.url.path), "query": str(request.query_params),
            "client_ip": client_ip, "user_agent": request.headers.get("user-agent", ""),
            "body": body, "hmac": "", "meta": {"headers": self._sanitize_headers(request.headers), "size": len(body), "duration": 0.0}
        }
        entry["hmac"] = self._sign_log(entry)
        return entry

    def _sanitize_headers(self, headers: Headers) -> Dict:
        try:
            return {k: "[REDACTED]" if k.lower() in REDACT_FIELDS else v for k, v in headers.items()}
        except Exception as e:
            self.logger.warning("Header sanitization failed", exc_info=True)
            return {}

    def _sign_log(self, log_data: Dict) -> str:
        try:
            h = hmac.new(HMAC_KEY, digestmod=hashlib.sha256)
            h.update(json.dumps(log_data, sort_keys=True).encode())
            return h.hexdigest()
        except Exception as e:
            self.logger.warning("Log signing failed", exc_info=True)
            return ""

    async def _emit_logs_async(self, log_data: Dict[str, Any]):
        try:
            log_data_dp = apply_differential_privacy(log_data, epsilon=0.01)
            log_event(f"[REQ] {log_data_dp['method']} {log_data_dp['path']}", level="INFO", meta={"ip": log_data_dp["client_ip"], "size": log_data_dp["meta"]["size"]})

            if log_data["path"].startswith("/auth") or log_data["path"].startswith("/admin"):
                await log_to_blockchain("request", log_data)
        except Exception as e:
            self.logger.warning("Async logging failed", exc_info=True)

    async def _log_response_async(self, request_id: str, path: str, status: int, duration: float, headers: Dict[str, str]):
        try:
            duration_dp = apply_differential_privacy({"duration": duration}, epsilon=0.01)["duration"]
            log_event(f"[RESP] {path} | {status} | {duration_dp:.3f}s", level="INFO", meta={"request_id": request_id, "duration_sec": duration_dp, "status_class": f"{status//100}xx"})
            if status >= 500:
                log_event(f"Server error on {path}", level="ALERT", meta={"request_id": request_id, "status": status, "duration": duration})
        except Exception as e:
            self.logger.warning("Async response logging failed", exc_info=True)