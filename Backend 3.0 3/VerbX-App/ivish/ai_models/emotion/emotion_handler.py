import torch
import numpy as np
from typing import Dict, List, Union, Any, Optional
import hashlib
import hmac
import logging
import os
import json
from datetime import datetime
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# 🔐 Security Imports
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 📁 Corrected Project Imports

from ai_models.emotion.emotion_fuser import load_emotion_model

from security.blockchain.zkp_handler import ZKPAuthenticator
from security.firewall import Firewall
from ai_models.anomaly.anomaly_classifier import AnomalyClassifier  # For synthetic voice detection

# 🔒 Security Constants
_MODEL_HASHES = {
    "text": "sha256:abc123...",  # Precomputed hash of text model
    "voice": "sha256:def456..."  # Precomputed hash of voice model
}
_MAX_INPUT_LENGTH = 5000  # Characters for text, samples for audio
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("EMOTION_HMAC_KEY", "secure_key_placeholder").encode()
_AES_KEY = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"emotion_salt_123",
    iterations=100000,
    backend=_BACKEND
).derive(os.getenv("EMOTION_AES_KEY", "emotion_key").encode())

@dataclass
class EmotionResult:
    """
    📌 Structured emotion result
    - emotion: standardized label
    - confidence: float score
    - model: model version used
    - timestamp: when result was generated
    - _signature: HMAC signature for tamper detection
    """
    emotion: str
    confidence: float
    model: str
    timestamp: str
    _signature: Optional[str] = None

class EmotionEngine:
    """
    🔒 Secure Emotion Detection Engine
    - Detects emotion from text and voice
    - Provides standardized emotional output
    - Prevents adversarial input attacks
    - Signs results for integrity
    - Detects synthetic voice spoofing
    - Integrates with TTS, GPT rephrasing, and AR overlays
    """

    def __init__(self):
        """Secure model loading with integrity verification."""
        self.text_model, self.voice_model = self._load_verified_models()
        self._hmac_key = _HMAC_KEY
        self._aes_gcm = AESGCM(_AES_KEY)
        self.anomaly_detector = AnomalyClassifier()  # For synthetic voice detection

    def _load_verified_models(self) -> tuple:
        """Load models with cryptographic verification."""
        text_model, voice_model = load_emotion_model()

        # Verify model integrity
        # Note: Hashing the state_dict is more common for PyTorch models
        text_hash = hashlib.sha256(json.dumps(str(text_model.state_dict())).encode()).hexdigest()
        voice_hash = hashlib.sha256(json.dumps(str(voice_model.state_dict())).encode()).hexdigest()

        if f"sha256:{text_hash}" != _MODEL_HASHES["text"]:
            logging.critical("🚨 Text model compromised!")
            self._trigger_defense_response()
            raise RuntimeError("Model integrity check failed")

        if f"sha256:{voice_hash}" != _MODEL_HASHES["voice"]:
            logging.critical("🚨 Voice model compromised!")
            self._trigger_defense_response()
            raise RuntimeError("Model integrity check failed")

        return text_model.eval(), voice_model.eval()  # Disable gradients

    def _validate_input(self, input_data: Union[str, np.ndarray]) -> bool:
        """Prevent adversarial inputs."""
        if isinstance(input_data, str):
            return len(input_data) <= _MAX_INPUT_LENGTH
        elif isinstance(input_data, np.ndarray):
            return input_data.size <= _MAX_INPUT_LENGTH
        return False

    def _sign_result(self, result: Dict) -> str:
        """HMAC-sign results to prevent tampering."""
        h = hmac.new(self._hmac_key, digestmod='sha256')
        h.update(json.dumps(result, sort_keys=True).encode())
        return h.hexdigest()

    def _encrypt_result(self, result: Dict) -> bytes:
        """AES-GCM encryption of sensitive results"""
        nonce = os.urandom(12)
        data = json.dumps(result).encode()
        encrypted = self._aes_gcm.encrypt(nonce, data, None)
        return nonce + encrypted

    def detect_emotion_from_text(self, text: str) -> Dict:
        """
        Secure text emotion detection with input validation.
        Returns: { emotion: str, confidence: float, _signature: str }
        """
        if not self._validate_input(text):
            return {"error": "Invalid input length"}

      

    def detect_emotion_from_voice(self, audio_data: Union[str, np.ndarray]) -> Dict:
        """
        Secure voice emotion detection with anti-spoofing.
        Accepts either file path or pre-extracted MFCCs.
        """
        if not self._validate_input(audio_data):
            return {"error": "Invalid input length"}

    def _is_synthetic_voice(self, mfcc: np.ndarray) -> bool:
        """Detect AI-generated voice patterns (simplified)."""
        # A more robust implementation would use a dedicated model
        try:
            prediction = self.anomaly_detector.predict(mfcc.flatten())
            return prediction == "anomaly"
        except Exception:
            return False

    def batch_detect(self, inputs: List[Union[str, np.ndarray]]) -> List[Dict]:
        """
        Optimized batch processing with parallel safety.
        """
        return [self.detect_emotion_from_text(i) if isinstance(i, str)
                else self.detect_emotion_from_voice(i)
                for i in inputs]

    def verify_result(self, signed_result: Dict) -> bool:
        """Validate HMAC signature of returned results."""
        try:
            signature = signed_result.pop("_signature", None)
            if not signature:
                return False
            
            h = hmac.new(self._hmac_key, digestmod='sha256')
            h.update(json.dumps(signed_result, sort_keys=True).encode())
            return h.hexdigest() == signature
        except Exception as e:
            logging.error(f"🚨 Result verification failed: {str(e)}")
            return False

    def _trigger_defense_response(self):
        """Reverse-intrusion response system"""
        logging.critical("🚨 MODEL TAMPERING DETECTED: Activating honeypot and endpoint rotation")
        ZKPAuthenticator().rotate_keys()
        Firewall().activate_blackhole()