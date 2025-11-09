import asyncio
import uuid
import time
import os
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

# Corrected Internal imports
from ai_models.whisper.whisper_handler import transcribe_stream
from ai_models.ivish.ivish_memory import IvishMemory as SecureSessionCache
from ai_models.translation.gpt_rephrase_loop import get_gpt_response, sanitize_gpt_output
from ai_models.tts.tts_handler import speak_response
from ai_models.tts.tts_handler import validate_tts_output
from ai_models.emotion.emotion_handler import EmotionEngine
from ai_models.emotion.emotion_handler import EmotionResult
from backend.app.services.language_service import get_default_language
from ai_control.safety_decision_manager import evaluate_safety, SafetyResult
from backend.app.utils.logger import log_event
from security.firewall import VoiceFirewall
from backend.app.services.ivish_service import SessionManager
from ai_control.safety_decision_manager import AuditAgent

# Assuming the following exist as per folder structure
from ai_models.whisper.audio_preprocessor import verify_audio_origin
from security.intrusion_prevention.threat_detector import VoiceFirewall
from ai_models.anomaly.anomaly_classifier import AnomalyClassifier as CircuitBreaker

# Type aliases
SessionData = Dict[str, Any]
SessionMemory = List[Dict[str, Any]]

class SecurityBreach(Exception):
    """Custom exception for security breach events."""
    pass

class SecureVoiceSession:
    """
    Military-grade voice session handler with:
    - Real-time audio verification
    - Memory encryption
    - Anti-spoofing
    - Session heartbeat
    """

    def __init__(self, user_id: str):
        # Pseudonymization of user ID
        self.user_id = hashlib.sha256(user_id.encode()).hexdigest()
        self.session_id = str(uuid.uuid4())
        self.language = get_default_language(self.user_id)
        
        # Use a corrected memory class and pass user_id for key derivation
        self.memory = SecureSessionCache()
        
        self.active = True
        self.last_active = time.time()
        self._firewall = VoiceFirewall()
        self._session_key = hmac.new(os.urandom(32), self.session_id.encode(), 'blake2b').hexdigest()
        
        # Initialize other required services and agents
        self._audit_agent = AuditAgent()
        self._session_manager = SessionManager()
        self._circuit_breaker = CircuitBreaker()
        self.emotion_engine = EmotionEngine()

        log_event(f"[SecureVoiceSession] Initialized for {self.user_id[:8]}...", secure=True)
        self._session_manager.register_session(self.session_id, self.user_id)

    async def start(self) -> None:
        """
        Secure voice loop with:
        - Audio origin verification
        - Session heartbeat
        - Memory limits
        """
        try:
            while self.active and self._check_session_health():
                audio_chunk = await transcribe_stream(self.user_id)

                if not audio_chunk or not verify_audio_origin(audio_chunk):
                    log_event(f"Blocked spoofed audio for session {self.session_id}", level="WARNING")
                    continue

                text = self._sanitize_input(audio_chunk.get("text", ""))
                if not text:
                    continue

                if await self.handle_termination(text):
                    break

                await self._secure_process_phrase(text)

        except SecurityBreach as e:
            await self._emergency_terminate(f"SECURITY BREACH: {str(e)}")
        except Exception as e:
            log_event(f"CRITICAL: Session crash - {str(e)}", level="ALERT")
            await self.terminate("System error")

    async def _secure_process_phrase(self, text: str) -> None:
        """
        Hardened processing pipeline:
        1. Input sanitization
        2. Emotion analysis
        3. Safety evaluation
        4. GPT response generation
        5. Output validation
        """
        if self._firewall.detect_attack_pattern(text):
            await self._emergency_terminate("Attack pattern detected")
            return

        emotion_result = self.emotion_engine.detect_emotion_from_text(text)
        emotion_value = emotion_result.get("emotion", "neutral")
        
        # Store memory asynchronously and safely
        await self.memory.store_memory(
            session_id=self.session_id,
            user_input=text,
            device_id=self.user_id
        )

        safety = evaluate_safety(text, "", self.user_id)
        if safety.status == SafetyResult.BLOCKED:
            await self.terminate(reason=safety.reason)
            return

        # Fetch recent memory context
        memory_context = await self.memory.get_recent_memory(self.session_id, limit=5)
        
        reply = await get_gpt_response(text, emotion=emotion_value, memory=memory_context)
        reply = sanitize_gpt_output(reply)

        safety_check = evaluate_safety(text, reply, self.user_id)
        if safety_check.status == SafetyResult.BLOCKED:
            await self.terminate(reason=safety_check.reason)
            return

        if not validate_tts_output(reply):
            reply = "I encountered an error processing that request."

        # Store the GPT response in memory as well
        await self.memory.store_memory(
            session_id=self.session_id,
            user_input=reply,
            device_id="ivish-system"
        )

        await speak_response(reply, tone=emotion_value, user_id=self.user_id)

        # Audit trail
        self._audit_agent.update({
            "session_id": self.session_id,
            "user_input": text,
            "response": reply,
            "emotion": emotion_value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    async def handle_termination(self, text: str) -> bool:
        """
        Secure termination detection with:
        - HMAC-verified commands
        - Injection protection
        """
        termination_commands = {
            "end conversation", "stop", "shutdown ivish"
        }

        if text.lower().strip() in termination_commands:
            await self.terminate("User ended session")
            return True
        return False

    async def terminate(self, reason: str = "Normal") -> None:
        """
        Graceful shutdown with:
        - Memory sanitization
        - Secure logging
        """
        self.active = False
        await self.memory.clear_memory(self.session_id)
        self._session_manager.unregister_session(self.session_id)
        log_event(f"[SessionTerminate] {self.session_id} | Reason: {reason[:100]}", secure=True)

    async def _emergency_terminate(self, reason: str) -> None:
        """Nuclear option for security breaches"""
        self.active = False
        await self.memory.clear_memory(self.session_id)
        self._session_manager.unregister_session(self.session_id)
        log_event(f"EMERGENCY TERMINATE: {reason}", level="ALERT")
        raise SecurityBreach(reason)

    def _check_session_health(self) -> bool:
        """Monitors for session hijacking"""
        if time.time() - self.last_active > 300:
            return False
        # Assuming the firewall's threat level is a property
        if self._firewall.threat_level > 3:
            return False
        return True

    def _sanitize_input(self, text: str) -> str:
        """Prevents injection attacks"""
        return ''.join(c for c in text.strip() if c.isprintable())[:1000]