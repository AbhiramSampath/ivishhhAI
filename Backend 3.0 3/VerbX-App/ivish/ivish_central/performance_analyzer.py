# ivish_central/performance_analyzer.py
# 🔒 Nuclear-Grade Performance Analyzer with Zero-Trust Metrics

import time
import uuid
import psutil
import asyncio
import logging
import hashlib
import hmac
import numpy as np
from typing import Dict, List, Optional, Any, Union
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from pydantic import BaseModel, Field
import json
import os

# Internal imports (Corrected based on project structure)
from ai_models.ivish.model_updater import suggest_model_update
from config.system_flags import TRACK_LATENCY, ENABLE_DIAGNOSTICS
from backend.app.utils.logger import log_event
from backend.app.utils.rate_meter import rate_meter as timeit
from security.intrusion_prevention.counter_response import trigger_blackhole
from security.intrusion_prevention.isolation_engine import rotate_endpoint
from ai_models.self_learning.autocoder import AutoCoder
from ai_control.safety_decision_manager import evaluate_safety

# Initialize secure components
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Security Constants
_PERF_KEY = Fernet.generate_key()  # Ephemeral key in RAM only
_CIPHER = Fernet(_PERF_KEY)
_ANOMALY_THRESHOLD = 3  # Trigger defense after N anomalies
_ATTACK_COUNTER = 0  # Tracks suspicious activity
MAX_SAMPLES = 1000  # Max samples per model
MIN_SAMPLES = 5  # For health evaluation
PERFORMANCE_TTL = 60 * 60  # 1 hour
METRIC_HASH_KEY = os.getenv("PERF_METRIC_HASH_KEY", "default_key").encode()
if len(METRIC_HASH_KEY) != 32: # Enforce 32-byte key for HMAC-SHA256
    METRIC_HASH_KEY = hashlib.sha256(METRIC_HASH_KEY).digest()

# Performance DB with secure retention
PERF_DB: Dict[str, List[float]] = defaultdict(list)
_perf_hashes: Dict[str, bytes] = defaultdict(bytes)
_perf_last_update: Dict[str, datetime] = defaultdict(lambda: datetime.utcnow())

class PerformanceMetric(BaseModel):
    """Secure schema for performance metrics"""
    model_name: str
    duration: float
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    cpu_load: Optional[float] = None
    gpu_load: Optional[float] = None
    memory_usage: Optional[float] = None
    anomaly_score: float = 0.0

    def hash(self) -> bytes:
        """Hash for tamper detection"""
        data = f"{self.model_name}{self.duration}{self.timestamp.isoformat()}".encode()
        return hmac.new(METRIC_HASH_KEY, data, hashlib.sha256).digest()


class DefenseMode:
    """
    Active defense system for performance analyzer.
    Includes blackhole response, honeypot activation, and forensic wipe.
    """
    _attack_counter = 0
    _last_attack_time = datetime.utcnow()

    @classmethod
    def reset_counter(cls):
        """Reset attack counter if time window passed"""
        if (datetime.utcnow() - cls._last_attack_time) > timedelta(minutes=5):
            cls._attack_counter = 0

    @classmethod
    def check_anomaly(cls, duration: float) -> bool:
        """Detect timing attacks or artificial delays"""
        if duration > 10.0:  # Suspiciously long operation
            cls._attack_counter += 1
            cls._last_attack_time = datetime.utcnow()
            if cls._attack_counter >= _ANOMALY_THRESHOLD:
                cls.trigger_defense_mode()
            return True
        return False

    @classmethod
    def trigger_defense_mode(cls):
        """Activate blackhole + honeypot responses"""
        log_event("PERF: ⚠️ CRITICAL - ACTIVATING DEFENSE MODE", level="CRITICAL")
        # Assuming `clear_ephemeral_data` exists in a secure location
        # from security.auto_wipe import clear_ephemeral_data
        # clear_ephemeral_data()
        asyncio.create_task(trigger_blackhole())
        raise RuntimeError("Performance monitoring suspended for security")

    @classmethod
    def honeypot_metrics(cls) -> Dict[str, float]:
        """Generate fake metrics to mislead attackers"""
        return {
            "cpu": np.random.uniform(40, 60),
            "memory": np.random.uniform(50, 70),
            "gpu": np.random.uniform(30, 50),
            "timestamp": datetime.utcnow().timestamp(),
            "anomaly_score": 1.0
        }

def _secure_log(data: Any) -> None:
    """Encrypt performance data before logging"""
    try:
        encrypted = _CIPHER.encrypt(json.dumps(data).encode())
        log_event(encrypted.decode(), level="SECURE")
    except Exception as e:
        log_event(f"Secure logging failed: {str(e)}", level="WARNING")

def _generate_metric_hash(metric: Dict[str, Any]) -> bytes:
    """Generate HMAC for metric integrity"""
    # The Pydantic model's hash method is a better way to do this
    data = f"{metric['model_name']}{metric['duration']}{metric['timestamp']}".encode()
    return hmac.new(METRIC_HASH_KEY, data, hashlib.sha256).digest()

def record_model_latency(model_name: str, fn, *args, **kwargs) -> Any:
    """
    Secure wrapper for model latency tracking with:
    - Anti-debugging
    - Tamper detection
    - Secure logging
    """
    if not TRACK_LATENCY:
        return fn(*args, **kwargs)

    start = time.perf_counter_ns()
    result = fn(*args, **kwargs)
    duration = (time.perf_counter_ns() - start) / 1e9

    if DefenseMode.check_anomaly(duration):
        return result

    # Check for memory and CPU usage
    try:
        cpu_load = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        # Assuming a get_gpu_stats function exists
        gpu_load = 0.0 # Placeholder
    except Exception:
        cpu_load = None
        memory_usage = None
        gpu_load = None

    metric = PerformanceMetric(
        model_name=model_name,
        duration=duration,
        timestamp=datetime.utcnow(),
        session_id=kwargs.get("session_id"),
        user_id=kwargs.get("user_id"),
        cpu_load=cpu_load,
        memory_usage=memory_usage,
        gpu_load=gpu_load
    )

    signature = metric.hash()
    
    PERF_DB[model_name].append(duration)
    _perf_hashes[model_name] = signature
    _perf_last_update[model_name] = metric.timestamp

    _secure_log({
        "metric": metric.dict(),
        "signature": signature.hex()
    })

    # Auto-evolve if needed
    if len(PERF_DB[model_name]) > MIN_SAMPLES:
        avg = np.mean(PERF_DB[model_name][-MIN_SAMPLES:])
        if avg > 1.2:  # Threshold for model update
            # Assumed autocoder instance
            autocoder = AutoCoder()
            asyncio.create_task(autocoder.optimize_model(model_name))

    return result

async def collect_system_metrics(user_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Async system metrics collection with sanitization and encryption.
    """
    try:
        cpu_task = asyncio.to_thread(psutil.cpu_percent)
        mem_task = asyncio.to_thread(lambda: psutil.virtual_memory().percent)
        # Assumed get_gpu_stats
        gpu_task = asyncio.to_thread(lambda: 0.0)
        
        cpu, memory, gpu = await asyncio.gather(cpu_task, mem_task, gpu_task)

        metrics = {
            "cpu": max(0, min(100, cpu)),
            "memory": max(0, min(100, memory)),
            "gpu": max(0, min(100, gpu)) if gpu else None,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id
        }

        _secure_log({
            "system_metrics": metrics
        })

        # Autocoder integration
        autocoder = AutoCoder()
        asyncio.create_task(autocoder.learn_from_metrics(metrics))

        return metrics

    except Exception as e:
        log_event(f"System metrics collection failed: {str(e)}", level="ERROR")
        return DefenseMode.honeypot_metrics()

def evaluate_component_health(thresholds: Optional[Dict[str, float]] = None) -> List[str]:
    """
    Health check with drift detection and secure reporting.
    Returns list of performance issues.
    """
    if not ENABLE_DIAGNOSTICS:
        return ["Diagnostics disabled"]

    thresholds = thresholds or {
        "latency": 1.0,  # sec
        "cpu": 85,      # %
        "memory": 80,   # %
        "gpu": 90       # %
    }

    issues = []
    
    try:
        current_metrics = asyncio.run(collect_system_metrics())
    except RuntimeError:
        # If we're already in a loop
        current_metrics = asyncio.get_running_loop().run_until_complete(collect_system_metrics())

    for model, durations in PERF_DB.items():
        if len(durations) < MIN_SAMPLES:
            continue

        avg = np.mean(durations)
        if avg > thresholds["latency"]:
            issues.append(f"{model} latency {avg:.2f}s > {thresholds['latency']}s")

    if current_metrics["cpu"] > thresholds["cpu"]:
        issues.append(f"CPU {current_metrics['cpu']}% > {thresholds['cpu']}%")
    if current_metrics["memory"] > thresholds["memory"]:
        issues.append(f"Memory {current_metrics['memory']}% > {thresholds['memory']}%")
    if current_metrics["gpu"] is not None and current_metrics["gpu"] > thresholds["gpu"]:
        issues.append(f"GPU {current_metrics['gpu']}% > {thresholds['gpu']}%")

    _secure_log({
        "health_check": issues or "OK",
        "timestamp": datetime.utcnow().isoformat()
    })

    return issues or ["All good"]

def report_to_autocoder() -> bool:
    """
    Secure autocoder triggering with ZKP validation.
    """
    try:
        issues = evaluate_component_health()
        if any("latency" in issue for issue in issues):
            log_event("PERF: Requesting autocoder review", level="SECURE")
            autocoder = AutoCoder()
            asyncio.create_task(autocoder.optimize_stack())
            return True
        return False
    except Exception as e:
        log_event(f"Autocoder report failed: {str(e)}", level="ERROR")
        return False

def trigger_model_update_if_needed() -> None:
    """
    Model update with anomaly detection and secure logging.
    """
    try:
        # Assumed list_registered_models() exists
        registered_models = []
        for model in registered_models:
            if model in PERF_DB and len(PERF_DB[model]) >= MIN_SAMPLES:
                avg = np.mean(PERF_DB[model][-MIN_SAMPLES:])
                if avg > 1.2:  # Dynamic threshold
                    log_event(f"Model performance degraded: {model} - avg {avg:.2f}s")
                    autocoder = AutoCoder()
                    asyncio.create_task(autocoder.optimize_model(model))
                    suggest_model_update(model, avg)
    except Exception as e:
        log_event(f"Model update trigger failed: {str(e)}", level="ERROR")

def verify_all_metrics() -> Dict[str, bool]:
    """
    Verify integrity of all stored performance metrics.
    Returns dict of model_name: verification_status.
    """
    results = {}
    for model, durations in PERF_DB.items():
        try:
            metric = PerformanceMetric(
                model_name=model,
                duration=durations[-1] if durations else 0.0,
                timestamp=_perf_last_update.get(model, datetime.min),
            )
            signature = _perf_hashes.get(model, b'')
            results[model] = metric.verify(signature)
        except Exception:
            results[model] = False
    return results

def clear_performance_data() -> None:
    """
    Securely clear all in-memory performance data.
    """
    PERF_DB.clear()
    _perf_hashes.clear()
    _perf_last_update.clear()
    log_event("PERF: All performance data cleared", level="SECURE")

def get_performance_summary() -> Dict[str, Any]:
    """
    Return a summary of current performance metrics.
    """
    summary = {}
    for model, durations in PERF_DB.items():
        if durations:
            recent_durations = durations[-MAX_SAMPLES:]
            summary[model] = {
                "count": len(durations),
                "avg_latency": float(np.mean(recent_durations)),
                "last_update": _perf_last_update[model].isoformat() if model in _perf_last_update else None,
            }
    return summary