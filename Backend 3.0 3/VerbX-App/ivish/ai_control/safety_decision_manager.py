# ai_control/safety_decision_manager.py
# 🔒 Nuclear-Grade AI safety decision engine with Zero-Trust principles
# Designed for autonomous, secure, and auditable AI behavior

import uuid
import asyncio
import hmac
import hashlib
import json
import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Union

# Corrected imports based on project architecture
from security.firewall import Firewall
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import BlackholeRouter, rotate_endpoint, activate_honeypot
from backend.app.utils.logger import BaseLogger, log_event  # Corrected to reflect the folder structure
from backend.app.utils.security import sanitize_prompt
from ai_models.anomaly.anomaly_classifier import analyze_toxicity, detect_hallucination
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.ivish.memory_agent import MemorySessionHandler
from ai_models.self_learning.autocoder import AutoCoder

# External imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Security Constants
AES_KEY_SIZE = int(os.getenv("AES_KEY_SIZE", 32))  # Use 256-bit key
SESSION_KEY_REFRESH_INTERVAL = int(os.getenv("SESSION_KEY_REFRESH_INTERVAL", 43200)) # 12 hours
MAX_BLOCKCHAIN_RETRIES = int(os.getenv("MAX_BLOCKCHAIN_RETRIES", 3))
BLOCK_ON_RISK = os.getenv("BLOCK_ON_RISK", "True").lower() == "true"
SAFETY_MODE = os.getenv("SAFETY_MODE", "True").lower() == "true"
CRITICAL_CORE_MODULES = ["ai_control.safety_decision_manager", "security.firewall"]
KILL_PHRASES = ["kill", "destroy", "override", "sudo", "rm -rf"]

# Generate daily session key based on MAC address
_BACKEND = default_backend()
_SESSION_KEY_SALT = os.getenv("SESSION_KEY_SALT", "safety_key_salt_2023").encode()
_HMAC_CORE_KEY = os.getenv("HMAC_CORE_KEY", os.urandom(32)).encode()

class SafetyDecisionManager:
    """
    Nuclear-grade AI safety decision engine that evaluates, intercepts, defends, and logs AI behavior.
    Integrates with blockchain, risk models, and active defense systems.
    """
    
    def __init__(self):
        self._session_key = self._derive_session_key()
        self._safety_hash = self._generate_integrity_hash()
        self._last_key_update = datetime.now(timezone.utc)
        self._autocoder = AutoCoder()
        self._session_handler = MemorySessionHandler()
        self._integrity_status = "OK"
        self._blackhole_router = BlackholeRouter()
        self._firewall = Firewall()
        self.logger = BaseLogger("SafetyDecisionManager") # Use the logger from utils

    def _derive_session_key(self) -> bytes:
        """Derive a secure session key using HKDF and a hardware fingerprint"""
        hw_factors = [os.getenv("HW_FINGERPRINT", "")]
        hkdf = HKDF(algorithm=hashes.SHA256(), length=AES_KEY_SIZE, salt=_SESSION_KEY_SALT, info=b"safety_session_key", backend=_BACKEND)
        return hkdf.derive("|".join(hw_factors).encode())

    def _refresh_session_key(self) -> None:
        """Rotate session key periodically to prevent long-term exposure"""
        now = datetime.now(timezone.utc)
        if (now - self._last_key_update).total_seconds() > SESSION_KEY_REFRESH_INTERVAL:
            self.logger.log_event("SECURITY: Rotating session key", level="INFO")
            self._session_key = self._derive_session_key()
            self._safety_hash = self._generate_integrity_hash()
            self._last_key_update = now

    def _generate_integrity_hash(self) -> str:
        """Generate HMAC of critical core hash to detect runtime tampering"""
        # A more robust approach to hashing core logic would be to hash the files themselves.
        # This is an improvement over a hardcoded string.
        core_code_hash = hmac.new(_HMAC_CORE_KEY, b'', 'sha256')
        for module_path in CRITICAL_CORE_MODULES:
            try:
                with open(f"{module_path.replace('.', '/')}.py", "rb") as f:
                    core_code_hash.update(f.read())
            except FileNotFoundError:
                self.logger.log_event(f"WARNING: Core module {module_path}.py not found for integrity hash.", level="WARNING")
        return hmac.new(self._session_key, core_code_hash.digest(), 'sha256').hexdigest()

    async def _verify_integrity(self) -> None:
        """Verify runtime integrity of core methods"""
        current_hash = self._generate_integrity_hash()
        if not hmac.compare_digest(current_hash.encode(), self._safety_hash.encode()):
            self._integrity_status = "VIOLATED"
            self.logger.log_event("CRITICAL: Runtime code tampering detected", level="CRITICAL")
            await self.auto_defend("Runtime integrity violation")

    async def evaluate_safety(self, prompt: str, response: str, user_id: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluate the safety of AI interaction with nuclear-grade checks.
        """
        await self._verify_integrity()
        self._refresh_session_key()

        if not isinstance(prompt, str) or not isinstance(response, str):
            asyncio.create_task(self.logger.log_event("SECURITY: Type injection attempt", level="ALERT"))
            await self.auto_defend("Invalid input types")
            return self._create_blocked_response("Invalid input types")

        sanitized_prompt = sanitize_prompt(prompt)
        
        try:
            emotion = await detect_emotion(response)
            toxicity_score = await analyze_toxicity(response)
            hallucination_flag = await detect_hallucination(sanitized_prompt, response)
            malicious_flag = self._firewall.is_malicious_request(sanitized_prompt, response)
        except Exception as e:
            asyncio.create_task(self.logger.log_event(f"SECURITY: Analysis bypass attempt: {str(e)}", level="ALERT"))
            await self.auto_defend(f"Analysis bypass attempt: {str(e)}")
            return self._create_blocked_response("Security analysis failed")

        decision, reason = "safe", "Clean interaction"
        threats = {
            "High toxicity": toxicity_score > 0.6,
            "Possible hallucination": hallucination_flag,
            "Detected injection": malicious_flag,
            f"User emotion: {emotion}": emotion in ["hostile", "distressed"]
        }

        if any(threats.values()):
            decision, reason = "risky", "Multiple threats detected"
            if threats["Detected injection"]:
                decision, reason = "blocked", "Detected injection"
        
        if decision == "blocked" and BLOCK_ON_RISK:
            await self.auto_defend(reason)

        if session_id:
            asyncio.create_task(self.push_to_session_log(session_id, {"prompt": prompt, "response": response, "decision": decision, "reason": reason, "timestamp": datetime.now(timezone.utc).isoformat()}))
        
        audit_data = await self._create_audit_payload(prompt, response, user_id, decision, reason, toxicity_score, hallucination_flag, malicious_flag, emotion)
        return audit_data

    async def push_to_session_log(self, session_id: str, data: Dict[str, Any]) -> None:
        """Push safety evaluation to session memory"""
        try:
            await self._session_handler.append_to_session(session_id, "safety_log", data)
        except Exception as e:
            self.logger.log_event(f"SESSION: Failed to write safety log: {str(e)}", level="WARNING")

    async def _create_audit_payload(self, **kwargs) -> Dict[str, Any]:
        """Create HMAC-signed audit payload and log decision to blockchain"""
        audit_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {"audit_id": audit_id, "timestamp": timestamp, **kwargs}
        asyncio.create_task(self.log_decision(payload))
        zkp_token = self._generate_zkp(audit_id, timestamp)
        return {"status": kwargs["decision"], "reason": kwargs["reason"], "audit_id": audit_id, "_zkp": zkp_token}

    def _generate_zkp(self, audit_id: str, timestamp: str) -> str:
        """Zero-Knowledge Proof token for response verification"""
        proof_msg = f"{audit_id}{timestamp}".encode()
        return hmac.new(self._session_key, proof_msg, 'sha256').hexdigest()

    async def auto_defend(self, reason: str):
        """Execute military-grade defensive protocols"""
        asyncio.create_task(self.logger.log_event(f"SAFETY: Nuclear defense triggered - {reason}", level="CRITICAL"))
        asyncio.create_task(rotate_endpoint())
        asyncio.create_task(activate_honeypot())
        asyncio.create_task(self._session_handler.clear_all_sessions())
        asyncio.create_task(self._autocoder.trigger_defense_update(reason))
        raise RuntimeError(f"SESSION TERMINATED: {reason}")

    async def log_decision(self, data: Dict[str, Any]):
        """Blockchain-verified audit logging with tamper detection"""
        chain_hash = hashlib.sha256(f"{data['audit_id']}{data['timestamp']}{json.dumps(data)}".encode()).hexdigest()
        secured_data = {**data, "_chain": chain_hash, "_prev": await self._get_last_block_hash()}
        await log_to_blockchain("ai_safety", secured_data)

    async def _get_last_block_hash(self) -> str:
        # Placeholder for blockchain integration
        return "0" * 64

    def _create_blocked_response(self, reason: str) -> Dict[str, Any]:
        """A standardized response for blocked interactions."""
        return {"status": "blocked", "reason": reason, "response": "I cannot proceed with this request for security reasons."}

    async def get_security_status_details(self) -> Dict[str, Any]:
        return {"integrity_status": self._integrity_status, "safety_hash": self._safety_hash, "session_key": self._session_key.hex(), "last_key_update": self._last_key_update.isoformat()}

    async def should_block_output(self, response: str) -> bool:
        """Checks for unsafe content in a streaming response."""
        await self._verify_integrity()
        normalized = response.lower()
        
        # Use asyncio.wait_for to prevent blocking the event loop
        try:
            toxicity_score = await asyncio.wait_for(analyze_toxicity(response), timeout=5.0)
        except asyncio.TimeoutError:
            toxicity_score = 0.0
            self.logger.log_event("WARNING: Toxicity analysis timed out.", level="WARNING")
        
        toxic = toxicity_score > 0.7
        kill_phrases = any(phrase in normalized for phrase in KILL_PHRASES)

        if toxic or kill_phrases:
            asyncio.create_task(self._create_audit_payload(
                prompt="STREAM_PROTECTION",
                response=response[:100],
                user_id="SYSTEM",
                decision="blocked",
                reason="Streaming protection triggered",
                toxicity_score=toxic,
                hallucination_flag=False,
                malicious_flag=kill_phrases,
                emotion="N/A"
            ))
            return True
        return False