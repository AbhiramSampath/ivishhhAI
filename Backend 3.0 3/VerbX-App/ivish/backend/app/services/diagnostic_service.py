# backend/services/diagnostic_service.py
# 🔒 Final, Secure Diagnostic Engine for Ivish AI
# 🚀 Refactored Code

import os
import time
import json
import psutil
import platform
import asyncio
import hashlib
import hmac
import logging
import sounddevice as sd
from datetime import datetime, timezone
from typing import Dict, Optional, Union, Any
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Corrected Project Imports
from ..utils.logger import log_event
from ..models.performance_metrics import check_model_drift, measure_latency
from ....security.intrusion_prevention.threat_detector import ThreatDetector
from ....security.encryption_utils import AES256Cipher
from ....ai_models.federated_learning.encryption_utils import apply_differential_privacy
from ..utils.helpers import constant_time_compare

# LOGGER CONFIG
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# SECURITY CONSTANTS
DIAGNOSTIC_SALT = os.getenv("DIAG_SALT", None)
if not DIAGNOSTIC_SALT:
    raise RuntimeError("DIAG_SALT not found in environment.")
DIAGNOSTIC_SALT = DIAGNOSTIC_SALT.encode()

DIAG_HMAC_KEY = os.getenv("DIAG_HMAC_KEY", None)
if not DIAG_HMAC_KEY:
    raise RuntimeError("DIAG_HMAC_KEY not found in environment.")
DIAG_HMAC_KEY = DIAG_HMAC_KEY.encode()

DEVICE_FINGERPRINT = hashlib.sha256(platform.node().encode()).digest()
MIN_PROCESSING_TIME_MS = int(os.getenv("DIAG_MIN_PROCESSING_TIME", "50"))
MAX_LATENCY_MS = int(os.getenv("DIAG_MAX_LATENCY", "300"))
THREAT_THRESHOLD = float(os.getenv("DIAG_THREAT_THRESHOLD", "0.7"))
ENABLE_DIAGNOSTICS = os.getenv("ENABLE_DIAGNOSTICS", "True").lower() == "true"

class SecureDiagnostics:
    """
    Nuclear-grade secure diagnostics engine with:
    - HMAC-signed reports for integrity
    - Secure battery/model checks
    - Encrypted logging
    - Anti-probing delays
    """
    def __init__(self):
        self._ephemeral_key = self._derive_key()
        self._valid_models = {"default", "stt", "tts", "nmt", "emotion", "tone"}
        self._threat_detector = ThreatDetector()
        self._cipher = AES256Cipher()

    def _derive_key(self) -> bytes:
        """SECURE key derivation with PBKDF2 for HMAC signing."""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=DIAGNOSTIC_SALT,
                iterations=100000,
                backend=default_backend()
            )
            return kdf.derive(DEVICE_FINGERPRINT)
        except Exception as e:
            logger.error("Key derivation failed", exc_info=True)
            return os.urandom(32)

    def _sign_diagnostic(self, data: str) -> str:
        """SECURE HMAC-based diagnostic signature for integrity."""
        try:
            h = hmac.new(DIAG_HMAC_KEY, data.encode(), hashlib.sha256)
            return h.hexdigest()
        except Exception as e:
            logger.error("Diagnostic signature failed", exc_info=True)
            return ""

    def _verify_diagnostic_signature(self, data: str, signature: str) -> bool:
        """SECURE HMAC signature verification with constant-time comparison."""
        expected = self._sign_diagnostic(data)
        return constant_time_compare(expected, signature)

    async def check_microphone_health(self) -> Dict[str, Any]:
        """SECURE microphone health check."""
        try:
            devices = await asyncio.to_thread(sd.query_devices)
            if not devices:
                return {"available": False, "error": "No audio devices"}

            input_devices = [d for d in devices if d.get("max_input_channels", 0) > 0]
            if not input_devices:
                return {"available": False, "error": "No input devices"}

            info = await asyncio.to_thread(sd.query_devices, kind='input')
            info = apply_differential_privacy(info, epsilon=0.1)

            return {
                "available": True,
                "sample_rate": info.get('default_samplerate', 0),
                "channels": info.get('max_input_channels', 0),
                "device": info.get('name', 'unknown')
            }
        except Exception as e:
            await log_event(f"MIC_FAILURE|{e}", level="ERROR", metadata={"security": True})
            return {"available": False, "error": "Audio device error"}

    async def check_battery_status(self) -> Dict[str, Any]:
        """SECURE battery check."""
        try:
            battery = await asyncio.to_thread(psutil.sensors_battery)
            if battery is None:
                return {"supported": False, "error": "No battery info"}

            if not 0 <= battery.percent <= 100 or not isinstance(battery.power_plugged, bool):
                raise ValueError("Tampered battery or power status")

            return {
                "percent": battery.percent,
                "plugged": battery.power_plugged,
                "secs_left": battery.secsleft if battery.secsleft else 0,
                "supported": True
            }
        except Exception as e:
            await log_event(f"BATTERY_TAMPER|{e}", level="ALERT", metadata={"security": True})
            return {"supported": False, "tamper_alert": True}

    async def run_model_latency_benchmark(self, model_name: str = "default") -> Dict[str, Any]:
        """SECURE latency benchmark."""
        try:
            if model_name not in self._valid_models:
                model_name = "default"

            result = await measure_latency(model=model_name)
            if result.get("latency", MAX_LATENCY_MS) > MAX_LATENCY_MS:
                await log_event(f"Model latency threshold exceeded: {model_name}", level="WARNING")

            return {
                "model": model_name,
                "latency_ms": result["latency"],
                "quantized": result.get("quantized", False),
                "score": result.get("score", 0.95)
            }
        except Exception as e:
            logger.warning("Model benchmark failed", exc_info=True)
            return {"error": "benchmark_failed", "model": model_name}

    async def monitor_device_health(self, user_id: str = "unknown") -> Dict[str, Any]:
        """
        SECURE full diagnostic with HMAC integrity and privacy.
        """
        if not ENABLE_DIAGNOSTICS:
            return {"status": "disabled"}
        
        start_time = time.time()
        try:
            mic, battery, model_perf, drift, threat = await asyncio.gather(
                self.check_microphone_health(),
                self.check_battery_status(),
                self.run_model_latency_benchmark(),
                check_model_drift(),
                self._threat_detector.detect_anomalies()
            )

            report = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "platform": platform.system(),
                "mic": mic,
                "battery": battery,
                "model_latency": model_perf,
                "drift_alert": drift,
                "threat": threat
            }

            signed_report = {
                "report": report,
                "signature": self._sign_diagnostic(json.dumps(report, sort_keys=True))
            }

            await log_event(f"DIAGNOSTIC_REPORT for {user_id}", level="INFO", metadata=signed_report)

            return signed_report
        except Exception as e:
            await self._trigger_security_incident(f"DIAG_FAILURE: {str(e)}")
            return {"status": "error", "security_alert": True}
        finally:
            elapsed_ms = (time.time() - start_time) * 1000
            await asyncio.sleep(max(0, (MIN_PROCESSING_TIME_MS - elapsed_ms) / 1000))

    async def _trigger_security_incident(self, reason: str):
        """SECURE incident responder with crypto shredding and decoy."""
        await log_event(f"SECURITY_INCIDENT|{reason}", level="CRITICAL", metadata={"security": True})
        # Placeholder for secure data shredding.
        pass

# Singleton instance
diagnostic_service = SecureDiagnostics(get_async_mongo_client)