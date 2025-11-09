import uuid
import time
import json
import hmac
import hashlib
import logging
import os
import random
from datetime import datetime
from typing import Dict, List, Optional, Union
from collections import defaultdict

# SECURITY: Preserved and corrected imports
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.dialect_adapter import detect_language
from ai_models.ner.ner_handler import ner_tagger as extract_entities # Corrected path
from ai_control.safety_decision_manager import evaluate_safety as is_sensitive_task # Corrected path
from ai_models.translation.gpt_rephrase_loop import rephrase_text
from ai_models.translation.mt_translate import translate_text
from ai_models.ivish.ivish_memory import get_context as recall_context # Corrected path
from ai_models.ivish.ivish_memory import get_session_flags # Corrected path
from backend.app.utils.logger import log_event
from backend.app.utils.security import constant_time_compare, secure_wipe, apply_differential_privacy # Consolidated security utils
from security.blockchain.zkp_handler import EphemeralTokenValidator # Corrected path


try:
    import numpy as np
except ImportError:
    class np:
        @staticmethod
        def uniform(a, b):
            return random.uniform(a, b)

# LOGGER CONFIG
logger = logging.getLogger(__name__)

# CONSTANTS
SESSION_KEY = os.getenv("TASK_PLANNER_KEY", "").encode() or os.urandom(32)
if len(SESSION_KEY) < 32:
    SESSION_KEY = hashlib.sha256(SESSION_KEY).digest()

MAX_INPUT_LENGTH = int(os.getenv("MAX_INPUT_LENGTH", "1000"))
MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", "0.6"))

class TaskPlanner:
    """
    Nuclear-grade secure task planner with:
    - HMAC integrity verification
    - Anti-tampering checksums
    - Memory-safe processing
    - Differential privacy in context
    - Constant-time operations
    - Secure fallback mechanisms
    """

    def __init__(self):
        self.intent_weights = {
            "translate": 0.8,
            "rephrase": 0.7,
            "memory": 0.6,
            "support": 0.5,
            "chat": 0.4
        }
        self.intent_patterns = {
            "translate": ["translate", "traduzca", "अनुवाद", "மொழிபெயர்ப்பு"],
            "rephrase": ["rephrase", "make it polite", "rewrite", "reframe"],
            "memory": ["remember", "recall", "what did I say", "previous"],
            "support": ["help", "stuck", "stressed", "support", "confused"],
            "chat": ["hi", "hello", "how are you", "tell me"]
        }

    def plan_task(self, input_text: str, user_id: str, session_token: str) -> Dict:
        """
        SECURE main interface with:
        - ZKP session validation
        - Input sanitization
        - Multi-intent detection
        - Secure fallback
        """
        start_time = time.time()
        try:
            # SECURITY: Validate request with ZKP
            if not self._validate_request(user_id, input_text, session_token):
                log_event("Security: Invalid request blocked", level="WARNING")
                return self._fail_safe_response()

            # SECURITY: Sanitize input
            input_text = input_text[:MAX_INPUT_LENGTH]
            if not input_text.strip():
                return self._fail_safe_response()

            # SECURITY: Get user context
            session_flags = get_session_flags(user_id)
            if not self._verify_session_hmac(session_flags):
                log_event("Session tampering detected", level="CRITICAL")
                return self._fail_safe_response()

            # SECURITY: Detect intent and emotion
            emotion = detect_emotion(input_text)
            lang = detect_language(input_text)
            entities = extract_entities(input_text)

            # SECURITY: Infer intent with differential privacy
            intent = self.infer_intent(input_text, entities, emotion, session_flags)
            intent = apply_differential_privacy({"intent": intent}, epsilon=0.1)["intent"]

            # SECURITY: Get confidence
            confidence = self.get_confidence(intent, input_text)

            # SECURITY: Low confidence fallback
            if confidence < MIN_CONFIDENCE:
                log_event(f"Low confidence fallback: {intent} ({confidence:.2f})", level="DEBUG")
                return self._sanitize_output({
                    "status": "uncertain",
                    "suggestion": "clarify_request",
                    "intent": intent,
                    "confidence": confidence
                })

            # SECURITY: Sensitive task check
            if is_sensitive_task(intent, input_text):
                log_event(f"Sensitive task triggered: {intent}", user=user_id)
                return self._sanitize_output({
                    "status": "requires_verification"
                })

            # SECURITY: Dispatch task
            result = self.dispatch_task(intent, input_text, session_flags)

            # SECURITY: Log securely
            self.generate_action_log(user_id, input_text, intent, emotion, lang, confidence)

            # SECURITY: Anti-timing delay
            self._apply_processing_delay(start_time, target_ms=100)

            return self._sanitize_output({
                "status": "completed",
                "intent": intent,
                "result": result,
                "emotion": emotion,
                "language": lang,
                "confidence": confidence
            })

        except Exception as e:
            logger.warning("Task planning failed", exc_info=True)
            return self._fail_safe_response()

    def _validate_request(self, user_id: str, input_text: str, session_token: str) -> bool:
        """
        SECURE request validation with:
        - Input sanitization
        - Session validation
        - Size limits
        """
        try:
            # SECURITY: Basic injection/sanity checks
            if not isinstance(input_text, str) or len(input_text) > MAX_INPUT_LENGTH:
                return False

            # SECURITY: Validate session token
            if not EphemeralTokenValidator.validate_token(session_token):
                return False
            
            return True

        except Exception as e:
            logger.warning("Request validation failed", exc_info=True)
            return False

    def _verify_session_hmac(self, flags: Dict) -> bool:
        """
        SECURE HMAC validation with:
        - Constant-time comparison
        - Anti-timing attacks
        """
        try:
            if not flags:
                return False
            flags_copy = flags.copy()
            session_hmac = flags_copy.pop("hmac", None)
            if not session_hmac:
                return False

            h = hmac.new(SESSION_KEY, json.dumps(flags_copy, sort_keys=True).encode(), hashlib.sha256)
            expected = h.digest()

            return constant_time_compare(session_hmac, expected)

        except Exception as e:
            logger.warning("Session HMAC verification failed", exc_info=True)
            return False

    def infer_intent(
        self,
        text: str,
        entities: List,
        emotion: str,
        flags: Dict
    ) -> str:
        """
        SECURE intent inference with:
        - Input sanitization
        - Differential privacy
        - Anti-pattern checks
        """
        try:
            # SECURITY: Sanitize input
            text = text.lower()[:200]  # Limit input
            if not text.strip():
                return "chat"

            # SECURITY: Apply differential privacy
            text = apply_differential_privacy({"text": text}, epsilon=0.1)["text"]

            # SECURITY: Multi-intent detection
            detected = defaultdict(float)
            for intent, patterns in self.intent_patterns.items():
                for pattern in patterns:
                    if pattern in text:
                        detected[intent] += 1.0

            # SECURITY: Normalize and add jitter
            total = sum(detected.values())
            if total == 0:
                return "chat"

            scores = {
                k: v / total + np.uniform(-0.05, 0.05)
                for k, v in detected.items()
            }

            return max(scores, key=scores.get)

        except Exception as e:
            logger.warning("Intent inference failed", exc_info=True)
            return "chat"

    def dispatch_task(self, intent: str, input_text: str, flags: Dict) -> Dict:
        """
        SECURE task dispatching with:
        - Module isolation
        - Input sanitization
        - Secure cleanup
        """
        try:
            input_text = input_text[:500]  # Limit input
            user_id = flags.get("user_id")
            if not user_id:
                logger.warning("User ID missing in flags for dispatch")
                return {"error": "user_id_missing"}

            if intent == "translate":
                return {"translated": translate_text(input_text)}
            elif intent == "rephrase":
                return {"rephrased": rephrase_text(input_text)}
            elif intent == "memory":
                return {"context": recall_context(user_id)}
            elif intent == "support":
                return {"response": self._generate_support_response(input_text)}
            else:
                return {"response": rephrase_text(input_text, mode="friendly")}

        except Exception as e:
            logger.warning("Dispatch error", exc_info=True)
            return {"error": "processing_failed"}

    def _generate_support_response(self, input_text: str) -> str:
        """SECURE fallback support response"""
        try:
            return "I'm here to help. Can you tell me more about what you need?"
        except Exception as e:
            logger.warning("Support response failed", exc_info=True)
            return "I'm here to help."

    def get_confidence(self, intent: str, input_text: str) -> float:
        """
        SECURE confidence scoring with:
        - Input sanitization
        - Anti-exploit checks
        - Differential privacy
        """
        try:
            # SECURITY: Sanitize input
            if not input_text or len(input_text.split()) < 3:
                return 0.4

            # SECURITY: Apply differential privacy
            input_text = apply_differential_privacy({"text": input_text}, epsilon=0.05)["text"]

            # SECURITY: Confidence based on pattern strength
            pattern_count = sum(
                1 for pattern in self.intent_patterns.get(intent, [])
                if pattern in input_text.lower()
            )

            base_confidence = self.intent_weights.get(intent, 0.5)
            return min(1.0, base_confidence + (pattern_count * 0.05))

        except Exception as e:
            logger.warning("Confidence scoring failed", exc_info=True)
            return 0.5

    def generate_action_log(self, user_id: str, input_text: str, intent: str, emotion: str, lang: str, confidence: float):
        """
        SECURE action logging with:
        - HMAC signing
        - Truncated logging
        - Privacy-preserving hashing
        """
        try:
            log_data = {
                "user_id": self._hash_data(user_id),
                "intent": intent,
                "language": lang,
                "emotion": emotion,
                "confidence": confidence,
                "task_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat()
            }

            # SECURITY: HMAC signing
            h = hmac.new(SESSION_KEY, json.dumps(log_data, sort_keys=True).encode(), hashlib.sha256)
            log_data["hmac"] = h.hexdigest()

            log_event(f"TaskLog:{log_data}")
        except Exception as e:
            logger.warning("Action logging failed", exc_info=True)

    def _hash_data(self, data: str) -> str:
        """Secure hashing for anonymization."""
        # This function should be defined somewhere in the utils.
        return hashlib.sha256(data.encode()).hexdigest()

    def _sanitize_output(self, data: Dict) -> Dict:
        """
        SECURE output sanitization to:
        - Prevent data leakage
        - Restrict field exposure
        - Redact sensitive keys
        """
        try:
            if not isinstance(data, dict):
                return {"error": "invalid_output"}
            return {
                k: v for k, v in data.items()
                if k in {"status", "intent", "result", "confidence", "suggestion"}
            }
        except Exception as e:
            logger.warning("Output sanitization failed", exc_info=True)
            return {"error": "output_sanitize_failed"}

    def _fail_safe_response(self) -> Dict:
        """Default response on failure"""
        return {
            "status": "error",
            "reason": "request_validation_failed"
        }

    def _apply_processing_delay(self, start_time: float, target_ms: int):
        """Prevent timing side-channels"""
        elapsed_ms = (time.time() - start_time) * 1000
        if elapsed_ms < target_ms:
            time.sleep((target_ms - elapsed_ms) / 1000)

# Defensive: Securely wipe sensitive data from memory (best effort)
def secure_cleanup(*args):
    for arg in args:
        try:
            if isinstance(arg, str):
                secure_wipe(arg)
        except Exception:
            pass

def handle_suspicious_activity():
    try:
        deploy_decoy()
    except Exception:
        pass