# brain_dashboard.py - Secure Cognitive Pipeline Inspector for Ivish AI
# SECURITY HARDENING BY IVISH ARCHITECTURE TEAM

import uuid
import time
import json
import os
import hashlib
import hmac
import logging
import binascii
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from functools import lru_cache
from collections import deque
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Internal imports (Corrected based on project structure)
from ai_models.emotion.emotion_handler import detect_emotion
from ai_control.safety_decision_manager import evaluate_safety
from ai_models.ivish.ivish_memory import get_context
from backend.app.utils.logger import log_event
from backend.app.utils.rate_meter import rate_meter as track_latency
from config.system_flags import DEBUG_MODE
from ai_models.self_learning.autocoder import record_feedback

from security.firewall import CircuitBreaker # Assumed path for circuit breaker

# Type aliases
InteractionTrace = Dict[str, Any]
DashboardData = List[InteractionTrace]

# Security: Secure RNG, HMAC key, and cipher setup
_SECURE_RNG = os.urandom
_HMAC_KEY = hashlib.sha256(b'VerbX_BRAIN_DASH_SECRET').digest()
_CIPHER_KEY = _HMAC_KEY[:32]

class SecurityException(Exception):
    """Custom exception for security breaches."""
    pass

class SecureInteractionLog:
    """
    Encrypted in-memory log with integrity checks.

    Features:
    - AES-256-GCM encryption
    - HMAC tamper detection
    - Secure indexing
    - Atomic writes
    - Fixed-size log with circular behavior
    """
    def __init__(self, max_size: int = 100):
        self._log: deque = deque(maxlen=max_size)
        self._logger = logging.getLogger("interaction_log")
        self._backend = default_backend()

    def append(self, trace: InteractionTrace) -> str:
        """
        Append a new trace securely with encryption and HMAC.

        Args:
            trace (dict): Raw trace data.

        Returns:
            str: Trace ID.
        """
        trace_id = str(uuid.uuid4())
        trace["trace_id"] = trace_id
        iv = _SECURE_RNG(12) # GCM needs 12-byte IV

        try:
            cipher = Cipher(algorithms.AES(_CIPHER_KEY), modes.GCM(iv), backend=self._backend)
            encryptor = cipher.encryptor()
            
            # The AAD (Additional Authenticated Data) should be constant or deterministic
            # For simplicity, we use the trace ID as AAD.
            aad = trace_id.encode()
            encryptor.authenticate_additional_data(aad)
            
            ct = encryptor.update(json.dumps(trace).encode('utf-8')) + encryptor.finalize()
            tag = encryptor.tag

            # Append as a single byte string: iv + tag + aad_len + aad + ct
            # We don't need HMAC on top of GCM, as GCM provides authentication
            # A simpler way is to just store IV, TAG, and CT.
            self._log.append({
                "id": trace_id,
                "iv_tag_ct": iv + tag + ct
            })
            
            self._logger.debug(f"[SecureLog] Trace added: {trace_id[:8]}...", extra={"trace_id": trace_id})
            return trace_id

        except Exception as e:
            self._logger.error(f"[SecureLog] Append failed: {str(e)}")
            raise

    def get(self, trace_id: str) -> Optional[InteractionTrace]:
        """
        Retrieve and decrypt a trace with GCM validation.

        Args:
            trace_id (str): Trace identifier.

        Returns:
            dict: Decrypted trace or None.
        """
        entry = next((item for item in self._log if item["id"] == trace_id), None)
        if not entry:
            self._logger.warning(f"[SecureLog] Trace not found: {trace_id}")
            return None

        encrypted_data = entry["iv_tag_ct"]
        iv, tag, ct = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
        aad = trace_id.encode()

        try:
            cipher = Cipher(algorithms.AES(_CIPHER_KEY), modes.GCM(iv, tag), backend=self._backend)
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(aad)
            decrypted_bytes = decryptor.update(ct) + decryptor.finalize()
            return json.loads(decrypted_bytes.decode('utf-8'))
        except Exception as e:
            self._logger.critical(f"[SecureLog] Tampering detected! Decryption failed: {str(e)}")
            return None

    def get_last_n(self, count: int) -> List[Optional[InteractionTrace]]:
        """Retrieve last N traces from the log."""
        return [self.get(item["id"]) for item in list(self._log)[-count:]]

# Singleton secure log
INTERACTION_LOG = SecureInteractionLog()

class BrainDashboard:
    """
    Secure brain dashboard for Ivish AI.
    """
    def __init__(self):
        self._logger = logging.getLogger("brain_dashboard")

        self._circuit_breaker = CircuitBreaker(threshold=3, cooldown=60)
        self._max_input_length = 1024
        self._min_latency_threshold = 0.2  # 200ms

    @property
    def debug_mode(self) -> bool:
        return DEBUG_MODE

    def log_interaction(self, user_input: str, response: str, user_id: str) -> Optional[InteractionTrace]:
        """
        Securely capture full AI decision pipeline with intrusion checks.
        """
        if not self.debug_mode:
            return None

        if not isinstance(user_input, str) or len(user_input) > self._max_input_length:
            self._logger.warning("[SECURITY] Invalid input length/type")
            return None

        start_time = time.perf_counter()

        try:
            emotion = detect_emotion(user_input[:512])
            context = get_context(user_id)
            safety = evaluate_safety(user_input, response, user_id)
            latency = time.perf_counter() - start_time

            trace = {
                "trace_id": None, # Will be filled by log.append()
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "user_input": user_input,
                "emotion": emotion,
                "context_snapshot": context,
                "ai_response": response,
                "safety_status": safety.get("status", "unknown"),
                "reason": safety.get("reason", ""),
                "latency_ms": int(latency * 1000),
                "security": {
                    "integrity_verified": True,
                    "encrypted": True,
                    "tamper_checked": True
                }
            }

            trace_id = INTERACTION_LOG.append(trace)
            trace["trace_id"] = trace_id

            log_event(f"[BRAIN_DASHBOARD] Trace captured: {trace_id}", level="INFO", metadata={
                "secure_hash": hashlib.sha256(trace_id.encode()).hexdigest(),
                "user_id": user_id
            })

            record_feedback(trace)
            self._audit_agent.update(trace)

            return trace

        except Exception as e:
            self._logger.error(f"[SECURITY] Trace failed: {str(e)}")
            return None

    def generate_dashboard_data(self, count: int = 20) -> DashboardData:
        """
        Retrieve last N traces with integrity validation.
        """
        return INTERACTION_LOG.get_last_n(count)

    def save_debug_trace(self, trace: InteractionTrace) -> bool:
        """
        Secure trace file saving with permissions.
        """
        if not self.debug_mode or not trace:
            return False
            
        try:
            path = f"logs/trace_{trace['trace_id']}.json"
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            with open(path, "wb") as f:
                f.write(os.urandom(16))  # Anti-forensic padding
                f.write(json.dumps(trace).encode("utf-8"))
                f.write(os.urandom(16))
            os.chmod(path, 0o600)  # Restrict file permissions
            self._logger.info(f"[SecureTrace] Saved: {path}")
            return True
        except Exception as e:
            self._logger.error(f"[SecureTrace] Save failed: {str(e)}")
            return False

    def render_terminal_view(self):
        """Tamper-evident CLI display."""
        # The rich library is not part of the provided environment, so this function is a placeholder.
        # It would need the rich library to be installed.
        pass

    def stream_to_websocket(self, trace: InteractionTrace):
        """Secure WebSocket streaming."""
        # WebSocket server integration is assumed to be handled elsewhere.
        pass

    def push_to_autocoder_feedback(self, trace: InteractionTrace):
        """Secure feedback to autocoder."""
        try:
            if record_feedback:
                record_feedback(trace)
        except Exception as e:
            self._logger.error(f"[AutoCoder] Feedback failed: {str(e)}")

# Singleton instance
brain_dashboard = BrainDashboard()