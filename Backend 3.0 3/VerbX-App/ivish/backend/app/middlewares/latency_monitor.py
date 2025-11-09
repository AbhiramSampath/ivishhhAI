# backend/middleware/latency_monitor.py
# 🔒 Nuclear-Grade Latency Monitor with Zero-Trust Decorator

import os
import time
import asyncio
import functools
import logging
import uuid
import subprocess
import json
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Internal imports - CORRECTED PATHS
from utils.logger import log_event
from ai_models.model_monitor import METRIC_THRESHOLDS
from security.zkp_handler import validate_metric_access
from security.blockchain.blockchain_utils import log_metric_event
from security.intrusion_prevention.counter_response import BlackholeRouter

# Security constants
_METRIC_SALT = b"latency_monitor_salt_2023"
MAX_LATENCY_LOGS = int(os.getenv("MAX_LATENCY_LOGS", 10000))
LATENCY_AES_KEY = os.getenv("LATENCY_AES_KEY", os.urandom(32)).encode()
if len(LATENCY_AES_KEY) != 32:
    log_event("CRITICAL: Invalid encryption key for latency monitor", alert=True)

class LatencyRecord:
    def __init__(self, tag: str, latency_ms: float, trace_id: str):
        self.tag = self._secure_hash(tag)
        self.latency_ms = round(latency_ms, 2)
        self.timestamp = time.time()
        self.trace_id = trace_id
        self.integrity_tag = self._generate_integrity_tag()

    def _secure_hash(self, tag: str) -> str:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=_METRIC_SALT,
            iterations=100_000
        )
        return kdf.derive(tag.encode()).hex()

    def _generate_integrity_tag(self) -> str:
        h = HMAC(LATENCY_AES_KEY, hashes.SHA256(), backend=default_backend())
        h.update(json.dumps(self.__dict__, sort_keys=True).encode())
        return h.finalize().hex()

class NuclearLatencyMonitor:
    def __init__(self):
        self._logs: List[LatencyRecord] = []
        self._lock = asyncio.Lock()
        self.config = {
            "enabled": True,
            "alert_on": True,
            "encrypt_logs": True,
            "log_to_blockchain": True,
            "max_logs": MAX_LATENCY_LOGS,
        }
        self.blackhole_router = BlackholeRouter()

    async def _log_latency(self, tag: str, start_time: float, trace_id: str):
        duration_ms = (time.monotonic() - start_time) * 1000
        record = LatencyRecord(tag, duration_ms, trace_id)

        if self.config["encrypt_logs"]:
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(LATENCY_AES_KEY), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = nonce + encryptor.tag + encryptor.update(json.dumps(record.__dict__).encode()) + encryptor.finalize()
            log_event("Latency metric recorded", metadata={"encrypted": encrypted.hex(), "trace": trace_id}, secure=True)
        else:
            log_event("Latency metric recorded", metadata=record.__dict__, secure=True)

        if self.config["log_to_blockchain"]:
            await log_metric_event({
                "tag": record.tag,
                "latency_ms": record.latency_ms,
                "trace_id": record.trace_id,
                "timestamp": record.timestamp
            })

        async with self._lock:
            if len(self._logs) >= self.config["max_logs"]:
                self._logs.pop(0)
            self._logs.append(record)

    def monitor(self, tag: str) -> Callable:
        secure_tag = self._secure_hash(tag)
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start = time.monotonic()
                trace_id = str(uuid.uuid4())
                try:
                    result = await func(*args, **kwargs)
                except Exception as e:
                    await log_event(f"LATENCY_FAIL | {tag} | {(time.monotonic() - start) * 1000:.2f}ms | ERROR: {str(e)}", severity="CRITICAL")
                    raise
                await self._log_latency(tag, start, trace_id)
                return result
            return async_wrapper
        return decorator

    def _secure_hash(self, tag: str) -> str:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=_METRIC_SALT,
            iterations=100_000
        )
        return kdf.derive(tag.encode()).hex()

    async def get_stats(self, tag: Optional[str] = None, user_token: str = "", zk_proof: str = "") -> Dict[str, Any]:
        if user_token and not await validate_metric_access(user_token, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}
        async with self._lock:
            relevant_logs = [r for r in self._logs if not tag or r.tag == self._secure_hash(tag)]
            if not relevant_logs: return {}
            latencies = [r.latency_ms for r in relevant_logs]
            return {
                "count": len(latencies), "avg": round(sum(latencies) / len(latencies), 2),
                "max": round(max(latencies), 2), "min": round(min(latencies), 2),
                "p50": round(sorted(latencies)[int(len(latencies) * 0.5)], 2),
                "p90": round(sorted(latencies)[int(len(latencies) * 0.9)], 2),
                "last_trace": relevant_logs[-1].trace_id, "timestamp": time.time()
            }

    async def clear_logs(self, user_token: str = "", zk_proof: str = "") -> Dict[str, Any]:
        if not await validate_metric_access(user_token, zk_proof): return {"status": "unauthorized", "error": "Access denied"}
        try:
            self._logs.clear()
            log_event("[LATENCY] Logs cleared securely", secure=True)
            return {"status": "cleared", "timestamp": time.time()}
        except Exception as e:
            log_event(f"[LATENCY] Clear logs failed: {str(e)}", alert=True)
            return {"status": "failed", "error": str(e)}

latency_monitor = NuclearLatencyMonitor()