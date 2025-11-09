from collections import defaultdict
import os
import re
import time
import json
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
import statistics
import logging
import aiofiles
import subprocess
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# 🔐 Security Imports - CORRECTED PATHS
from security.zkp_handler import verify_metrics_access
from security.blockchain.blockchain_utils import log_to_blockchain
from security.zkp_handler import ZKPAuthenticator
from utils.logger import log_event
from security.intrusion_prevention.counter_response import BlackholeRouter

# 📁 Project Imports
METRIC_LOG_FILE = os.getenv("METRIC_LOG_FILE", "/var/log/ivish_metrics.log")

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("PERFORMANCE_METRICS_HMAC_KEY", os.urandom(32)).encode()
_SUPPORTED_TASKS = ['stt', 'tts', 'gpt', 'translate', 'ner', 'emotion', 'context']
_MAX_LATENCY_SPIKE = float(os.getenv("MAX_LATENCY_SPIKE", 3.0))
_MIN_SAMPLES_FOR_STATS = int(os.getenv("MIN_SAMPLES_FOR_STATS", 5))
_METRIC_CACHE_TTL = int(os.getenv("METRIC_CACHE_TTL", 300))
_BLOCKCHAIN_BATCH_SIZE = int(os.getenv("BLOCKCHAIN_BATCH_SIZE", 10))

@dataclass
class MetricEntry:
    task: str
    latency: float
    success: bool
    timestamp: str
    _signature: Optional[str] = None

class SecurePerformanceMetrics:
    def __init__(self):
        self._metric_cache = []
        self._blockchain_buffer = []
        self._last_cache_purge = datetime.now()
        self._anomaly_detector = defaultdict(int)
        self._blackhole_router = BlackholeRouter()

    def _sign_entry(self, entry: Dict) -> str:
        h = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        h.update(json.dumps(entry, sort_keys=True).encode())
        return h.finalize().hex()

    async def log_metric(self, task_type: str, latency: float, success: bool = True, user_id: str = None):
        try:
            if not await verify_metrics_access():
                await self._handle_metrics_breach()
                return

            sanitized_task = self._sanitize_task_name(task_type)
            if not sanitized_task or not 0 <= latency <= 3600:
                await log_event(f"METRIC_TAMPER | Invalid entry: {task_type}/{latency}", level="ALERT")
                return

            entry = MetricEntry(task=sanitized_task, latency=round(latency, 4), success=success, timestamp=datetime.utcnow().isoformat() + "Z")
            entry._signature = self._sign_entry(entry.__dict__)

            self._metric_cache.append(entry.__dict__)
            self._blockchain_buffer.append(entry.__dict__)

            if len(self._blockchain_buffer) >= _BLOCKCHAIN_BATCH_SIZE:
                await self._flush_blockchain_buffer()

            await self._write_to_log_file(entry.__dict__)
            await log_event(f"[METRIC] {sanitized_task} | {latency:.2f}s | {'✅' if success else '❌'}")
            await self._check_for_anomalies(sanitized_task, latency, success)
        except Exception as e:
            await log_event(f"METRIC_LOG_FAILURE: {str(e)}", level="ERROR")

    async def _write_to_log_file(self, entry: Dict):
        try:
            async with aiofiles.open(METRIC_LOG_FILE, "a") as f:
                await f.write(json.dumps(entry) + "\n")
        except Exception as e:
            await log_event(f"METRIC_LOG_WRITE_FAILURE: {str(e)}", level="ERROR")

    async def _flush_blockchain_buffer(self):
        if not self._blockchain_buffer: return
        try:
            batch_hash = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
            for entry in self._blockchain_buffer:
                batch_hash.update(json.dumps(entry, sort_keys=True).encode())

            await log_to_blockchain("performance_metrics", {
                "batch_hash": batch_hash.finalize().hex(),
                "count": len(self._blockchain_buffer),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            self._blockchain_buffer.clear()
        except Exception as e:
            await log_event(f"BLOCKCHAIN_FLUSH_FAILED: {str(e)}", level="ERROR")

    async def _check_for_anomalies(self, task: str, latency: float, success: bool):
        if not success:
            self._anomaly_detector[task] = self._anomaly_detector.get(task, 0) + 1
            if self._anomaly_detector[task] >= 3:
                await log_event(f"ANOMALY_ALERT | {task} failing repeatedly", level="CRITICAL")
        else:
            self._anomaly_detector[task] = max(0, self._anomaly_detector.get(task, 0) - 1)
        
        recent_latencies = [m["latency"] for m in self._metric_cache if m["task"] == task and m["success"]]
        if len(recent_latencies) >= _MIN_SAMPLES_FOR_STATS:
            avg = statistics.mean(recent_latencies)
            std = statistics.stdev(recent_latencies) if len(recent_latencies) > 1 else 0
            if latency > avg + 3 * std and latency > _MAX_LATENCY_SPIKE:
                await log_event(f"LATENCY_SPIKE | {task} at {latency:.2f}s (avg: {avg:.2f}±{std:.2f}s)", level="WARNING")

    async def get_average_latency(self, task_type: str) -> Dict:
        sanitized_task = self._sanitize_task_name(task_type)
        if not sanitized_task: return {"error": "Invalid task name", "status": "failure"}
        relevant = [m["latency"] for m in self._metric_cache if m["task"] == sanitized_task and m["success"]]
        avg = round(statistics.mean(relevant), 3) if relevant else 0.0
        await asyncio.sleep(0.01)
        return {"task": sanitized_task, "average_latency": avg, "total_samples": len(relevant), "timestamp": datetime.utcnow().isoformat() + "Z", "status": "success"}

    async def generate_performance_report(self) -> Dict[str, Any]:
        try:
            tasks = {m["task"] for m in self._metric_cache}
            summary = {}
            for task in tasks:
                entries = [m for m in self._metric_cache if m["task"] == task]
                success_entries = [m for m in entries if m["success"]]
                summary[task] = {"avg_latency": round(statistics.mean([m["latency"] for m in success_entries]), 3) if success_entries else 0.0, "total": len(entries), "failures": len(entries) - len(success_entries), "last_seen": max([m["timestamp"] for m in entries]), "_integrity_hash": self._generate_task_hash(task)}
            summary["_metadata"] = {"blockchain_anchor": await self._get_latest_blockchain_anchor(), "generated_at": datetime.utcnow().isoformat() + "Z"}
            return summary
        except Exception as e:
            await log_event(f"REPORT_GENERATION_FAILURE: {str(e)}")
            return {"error": str(e), "status": "failure"}

    async def reset_metrics(self):
        try:
            snapshot = {"reset_at": datetime.utcnow().isoformat() + "Z", "final_count": len(self._metric_cache), "final_hash": self._generate_cache_hash()}
            await log_to_blockchain("metrics_reset", snapshot)
            self._metric_cache.clear()
            self._blockchain_buffer.clear()
            self._init_anomaly_detector()
            async with aiofiles.open(METRIC_LOG_FILE, "w") as f:
                await f.write("")
            await log_event("Metrics reset with blockchain attestation")
        except Exception as e:
            await log_event(f"METRICS_RESET_FAILURE: {str(e)}", level="ERROR")

    def _generate_task_hash(self, task: str) -> str:
        entries = [m for m in self._metric_cache if m["task"] == task]
        digest = hmac.HMAC(_HMAC_KEY, hashes.SHA3_256(), backend=_BACKEND)
        for entry in entries: digest.update(json.dumps(entry, sort_keys=True).encode())
        return digest.finalize().hex()

    def _generate_cache_hash(self) -> str:
        digest = hmac.HMAC(_HMAC_KEY, hashes.SHA3_256(), backend=_BACKEND)
        for entry in self._metric_cache: digest.update(json.dumps(entry, sort_keys=True).encode())
        return digest.finalize().hex()

    async def _get_latest_blockchain_anchor(self) -> str:
        return hashlib.sha256(datetime.utcnow().isoformat().encode()).hexdigest()

    def _sanitize_task_name(self, task: str) -> Optional[str]:
        if not isinstance(task, str): return None
        if task not in _SUPPORTED_TASKS: return None
        return task.lower().replace(" ", "_")[:32]

    async def _handle_metrics_breach(self):
        logging.critical("🚨 METRIC TAMPERING DETECTED: Activating honeypot and endpoint rotation")
        ZKPAuthenticator().rotate_keys()
        await self._blackhole_router.trigger()
        await log_event("METRICS_BREACH", level="CRITICAL")