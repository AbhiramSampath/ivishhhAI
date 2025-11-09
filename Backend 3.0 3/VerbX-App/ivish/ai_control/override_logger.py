import datetime
import logging
import asyncio
import os
import json
import base64
import glob
import subprocess
from typing import Any, Dict, Optional, Union
from functools import lru_cache
from contextlib import contextmanager

# Internal imports
from backend.app.utils.logger import BaseLogger, log_event
from ai_models.self_learning.autocoder import AutocoderTrainer
from security.intrusion_prevention.threat_detector import IntrusionDetector
from backend.app.services.ivish_service import SessionManager, terminate_session
from security.encryption_utils import encrypt_log as crypto_encrypt_log
from security.blockchain.blockchain_utils import log_to_blockchain as blockchain_log
from security.intrusion_prevention.counter_response import BlackholeRouter as BlackholeResponder

# External imports
from cryptography.fernet import Fernet

# Type aliases
LogData = Dict[str, Any]
LogEntry = Dict[str, Union[str, LogData, datetime]]

# --- Constants --- #
LOG_SENSITIVITY_THRESHOLD = float(os.getenv("LOG_SENSITIVITY_THRESHOLD", 0.8))
SENSITIVE_MODULES = os.getenv("SENSITIVE_MODULES", "auth,billing,payment").split(',')

class ManualOverrideController:
    """
    Centralized logging controller for Ivish AI runtime.
    """
    def __init__(self):
        self._init_logger()
        self._init_security()
        self._init_integrations()
        self._init_state()

    def _init_logger(self):
        self.logger = BaseLogger()
        self.audit_logger = logging.getLogger("audit")
        self.audit_logger.setLevel(logging.INFO)

    def _init_security(self):
        self._aes_key = os.getenv('OVERRIDE_AES_KEY', base64.urlsafe_b64encode(os.urandom(32)).decode())
        try:
            self._cipher = Fernet(self._aes_key)
        except Exception:
            raise ValueError("OVERRIDE_AES_KEY must be a valid 32-byte urlsafe base64-encoded key")
        self.intrusion_detector = IntrusionDetector()
        self.blackhole_responder = BlackholeResponder()

    def _init_integrations(self):
        self.autocoder = AutocoderTrainer()
        
    def _init_state(self):
        self.suppressed_modules = set(SENSITIVE_MODULES)
        self.sensitive_mode = False
        self._last_autocoder_fail = None

    async def log_decision(self, context: str, level: str, data: LogData):
        if not isinstance(context, str) or not isinstance(level, str):
            await self._handle_malicious_input()
            return
        
        timestamp = datetime.utcnow().isoformat() + 'Z'
        if len(str(data)) > 10_000: data = {"error": "Oversized payload truncated"}

        full_log: LogEntry = {"timestamp": timestamp, "context": context, "level": level.upper(), "data": self._sanitize_log_data(data)}

        if self.intrusion_detector.check_log_pattern(full_log): await self._activate_blackhole()

        if self._is_sensitive(data):
            encrypted_log = self._encrypt_log(full_log)
            await blockchain_log(encrypted_log)
            if not self.sensitive_mode: self.logger.debug("[Sensitive] Log encrypted and blockchain-stored")
        else: self._safe_log(level.upper(), full_log)

        await self._secure_stream_to_autocoder(data)

    async def suppress_logs(self, module_name: str):
        if not isinstance(module_name, str) or ';' in module_name: await self._handle_malicious_input(); return
        self.suppressed_modules.add(module_name)
        self.logger.info(f"Logging suppressed for: {module_name[:100]}")

    def restore_logs(self):
        self.logger.info("Restoring all suppressed logs.")
        self.suppressed_modules.clear()

    async def trace_to_blockchain(self, log_data: LogData):
        sanitized = {'timestamp': log_data.get('timestamp'), 'context': self._sanitize_str(log_data.get('context', '')), 'data': self._redact_sensitive(log_data.get('data', {}))}
        await blockchain_log(sanitized)

    def toggle_sensitive_mode(self, flag: bool):
        if not isinstance(flag, bool): self._handle_malicious_input(); return
        self.sensitive_mode = flag
        msg = f"SENSITIVE MODE {'ENABLED' if flag else 'DISABLED'}"
        self.logger.warning(msg, secure=True)

    def _is_sensitive(self, data: LogData) -> bool:
        risk = data.get("risk_level", 0)
        return isinstance(risk, (int, float)) and risk >= LOG_SENSITIVITY_THRESHOLD

    def _sanitize_log_data(self, data: Any) -> Any:
        if isinstance(data, dict): return {self._sanitize_str(k): self._sanitize_value(v) for k, v in data.items()}
        return self._sanitize_str(str(data))

    def _sanitize_str(self, s: Any) -> str:
        return ''.join(c for c in str(s) if c.isprintable()) if s else ''

    def _sanitize_value(self, v: Any) -> Any:
        if isinstance(v, dict): return self._sanitize_log_data(v)
        return self._sanitize_str(str(v))

    def _safe_log(self, level: str, message: LogEntry):
        if self._logging_allowed(): self.logger.log(level, message)

    def _logging_allowed(self) -> bool:
        return not self.sensitive_mode

    async def _secure_stream_to_autocoder(self, log_data: LogData):
        try:
            await self.autocoder.observe(log_data)
            self._last_autocoder_fail = None
        except Exception as e:
            self._last_autocoder_fail = datetime.utcnow()
            self.logger.error("Autocoder processing delayed", secure=True)
            if self._autocoder_fail_count() > 3: await self._activate_defense_mode()

    def _autocoder_fail_count(self) -> int:
        if self._last_autocoder_fail: return 0 if (datetime.utcnow() - self._last_autocoder_fail).seconds < 60 else 3
        return 0

    async def _activate_defense_mode(self):
        self.toggle_sensitive_mode(True); self.restore_logs();
        try: await terminate_session(None)
        except Exception as e: self.logger.error(f"Session termination failed: {str(e)}", secure=True)
        self.intrusion_detector.lockdown()

    async def _handle_malicious_input(self):
        self.intrusion_detector.record_attempt(); self.logger.critical("Malicious input pattern detected", secure=True)
        await self._activate_blackhole()

    async def _activate_blackhole(self):
        if self.intrusion_detector.threat_level > 2: await self.blackhole_responder.trigger()

    def _encrypt_log(self, data: LogEntry) -> bytes: return self._cipher.encrypt(json.dumps(data).encode())
    
    async def _secure_wipe(self, paths: list):
        for pattern in paths:
            for file_path in glob.glob(pattern):
                try: await asyncio.to_thread(subprocess.run, ['shred', '-u', file_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e: self.logger.error(f"Secure wipe failed for {file_path}: {e}")

override_logger = ManualOverrideController()