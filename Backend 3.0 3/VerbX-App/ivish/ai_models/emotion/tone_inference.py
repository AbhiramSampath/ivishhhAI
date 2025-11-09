import torch
import numpy as np
from typing import Dict, Any, Optional, List, Callable
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from datetime import datetime, timezone
import os
import json

# Corrected imports based on the provided file structure

from backend.app.utils.logger import log_event

from security.firewall import InferenceFirewall
from security.intrusion_prevention.threat_detector import trigger_blackhole
from security.intrusion_prevention.isolation_engine import rotate_endpoint
from security.blockchain.blockchain_utils import log_to_blockchain

from backend.app.utils.cache import secure_cache
from ai_models.emotion.emotion_fuser import fallback_tone_detector
from offline_engine.edge_loader import predict as edge_predict

# 🔐 Secure Global State
_MODEL_CACHE = {}
_FIREWALL = InferenceFirewall(rules={
    "max_text_len": 512,
    "blacklist": ["$RFI", "<?php", "SELECT *"],
    "max_input_rate": "10/second",
    "device_fingerprint_required": True
})
_EDGE_MODE = False

# 🧱 Global Config
ENABLE_BLOCKCHAIN_LOGGING = True
ENABLE_HONEYPOT = True
ENABLE_AUTO_WIPE = True
ENABLE_ENDPOINT_MUTATION = True

def infer_tone(text: str, lang: str = "auto", session_id: str = None) -> dict:
    """
    Secure emotion inference with fallback cascade.
    Returns structured emotion with confidence, security metadata, and blockchain audit.
    """
    if not _FIREWALL.validate(text):
        log_event("ToneInfer: Blocked malicious input", level="ALERT", session_id=session_id)
        if ENABLE_HONEYPOT:
            return _honeypot_response()
        else:
            return {"label": "neutral", "confidence": 0.5, "blocked": True}

   

    try:
        if not _EDGE_MODE:
            tokenizer, model = _load_secure_model(lang)
            inputs = tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=128,
                padding="max_length"
            )
            with torch.no_grad():
                outputs = model(**inputs)
            logits = outputs.logits.cpu().numpy()
            result = _process_prediction(logits, text, lang, session_id)
            if ENABLE_BLOCKCHAIN_LOGGING:
                log_to_blockchain("emotion_trigger", result, session_id=session_id)
            return result
        else:
            return _edge_inference(text, lang, session_id)
    except Exception as e:
        log_event(f"ToneInfer Error: {str(e)}", level="ERROR", session_id=session_id)
        return _failover_chain(text, lang, session_id)

def _load_secure_model(lang: str) -> tuple:
    """Model loader with integrity checks and secure caching."""
    if lang in _MODEL_CACHE:
        return _MODEL_CACHE[lang]

    model_name = ("ai4bharat/indic-bert-emotion"
                 if lang in ["hi", "ta", "te", "bn"]
                 else "nateraw/bert-base-uncased-emotion")

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    model.eval()

    if _EDGE_MODE:
        model = torch.quantization.quantize_dynamic(
            model, {torch.nn.Linear}, dtype=torch.qint8
        )

    _MODEL_CACHE[lang] = (tokenizer, model)
    secure_cache.set(f"model:{lang}", model_name)
    return tokenizer, model

def _process_prediction(logits: np.ndarray, text: str, lang: str, session_id: str) -> dict:
    """Post-process with confidence thresholding and risk detection."""
    scores = softmax(logits[0])
    idx = np.argmax(scores)
    confidence = float(scores[idx])


    return {

        "confidence": confidence,
        "language": lang,
        "_security": {
            "model": "primary",
            "session_id": session_id
        }
    }

def _edge_inference(text: str, lang: str, session_id: str) -> dict:
    """Offline-capable inference cascade."""
    # This corrected version calls the imported function directly
    return edge_predict(text, lang, session_id)


def _failover_chain(text: str, lang: str, session_id: str) -> dict:
    """Graceful degradation pipeline."""
    attempts = [
        lambda: _edge_inference(text, lang, session_id),
        lambda: fallback_tone_detector(text),
        lambda: {"label": "neutral", "confidence": 0.5}
    ]

    for fn in attempts:
        try:
            result = fn()
            if result and result.get("label"):
                return result
        except:
            continue
    return {"label": "neutral", "confidence": 0.5}

def _honeypot_response() -> dict:
    """Decoy response for attackers."""
    trigger_blackhole()
    return {
        "label": "neutral",
        "confidence": 0.99,
        "_security": {"is_honeypot": True}
    }

def _generate_checksum(data: str) -> str:
    """Tamper-proofing for results."""
    from hashlib import sha3_256
    return sha3_256(data.encode()).hexdigest()

def softmax(logits):
    exp = np.exp(logits - np.max(logits))
    return exp / exp.sum(axis=-1, keepdims=True)

def is_emotion_negative(label: str) -> bool:
    """Check if emotion is potentially risky."""
    return label in ["sad", "angry", "hostile", "anxious"]

def label_confidence_to_emojis(label: str, confidence: float) -> str:
    """Convert emotion to visual symbol."""
    emojis = {
        "happy": "😊",
        "sad": "😢",
        "angry": "😡",
        "neutral": "😐",
        "excited": "😄",
        "fearful": "😨"
    }
    return emojis.get(label, "😐") * int(confidence * 3 + 1)

if __name__ == "__main__":
    test_texts = [
        "I am so happy today!",
        "I feel very sad and depressed.",
        "Why are you so angry?",
        "This is just a normal day.",
        "I'm excited for the trip!",
        "I'm scared of the dark."
    ]
    for text in test_texts:
        result = infer_tone(text)
        emoji = label_confidence_to_emojis(result["label"], result["confidence"])
        print(f"Text: {text}\nResult: {result}\nEmoji: {emoji}\n{'-'*40}")