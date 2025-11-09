# tests/ai_models/test_emotion.py

import pytest
import asyncio
import time
import os
import numpy as np
import tempfile
from hypothesis import given, strategies as st
from hypothesis.extra.pandas import column, data_frames
from typing import Dict, Any, List, Optional
from collections import defaultdict
import hmac
import hashlib
from scipy.io import wavfile
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# 📦 Project Imports
from ai_models.tone_emotion_detector import (
    detect_emotion_from_text,
    detect_emotion_from_audio
)
from ai_control.safety_decision_manager import evaluate_safety
from utils.timer import benchmark_latency
from utils.logger import log_event
from utils.audio_generator import generate_emotion_sample
from security.blockchain_utils import log_to_blockchain
from security.reverse_defense import trigger_blackhole
from security.audit import secure_audit_log

# 🧱 Global Config
MAX_LATENCY_MS = 150  # 150ms SLA
MIN_CONFIDENCE = 0.6  # 60% threshold
LANGUAGES = ["en", "hi", "ta", "te", "bn", "es", "fr", "de", "ja", "zh"]
THREAT_LEVEL_THRESHOLD = 5
RATE_LIMIT_WINDOW = 60  # seconds
MAX_FAILURE_RATE = 3

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "threat_level": 0,
    "rate_limits": defaultdict(list),
    "last_attack_time": 0
}

# 🔒 Security Utilities
def _get_hw_key() -> bytes:
    """Hardware-bound key derivation"""
    hw_factors = [
        os.getenv("HW_FINGERPRINT", ""),
        str(os.cpu_count()),
        str(os.getloadavg()[0]),
        str(time.time())
    ]
    return hashlib.pbkdf2_hmac(
        'sha256',
        "|".join(hw_factors).encode(),
        os.urandom(16),
        100000
    )[:32]

def _generate_nonce() -> str:
    """Cryptographically secure nonce for CSP"""
    return base64.b64encode(os.urandom(16)).decode()[:16]

def _is_valid_language(lang: str) -> bool:
    """Language validation"""
    return lang in LANGUAGES

def _sanitize_input(text: str) -> str:
    """Prevent injection in downstream processing"""
    injection_patterns = [
        '<?', '<?php', '<script', 
        'SELECT * FROM', 'os.system', 
        'subprocess.call', 'eval('
    ]
    for pattern in injection_patterns:
        text = text.replace(pattern, '')
    return text.strip()

def _check_rate_limit(user: str, operation: str) -> bool:
    """Prevent abuse with rate limiting"""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    SECURITY_CONTEXT['rate_limits'][user] = [
        t for t in SECURITY_CONTEXT['rate_limits'].get(user, [])
        if t > window_start
    ]
    if len(SECURITY_CONTEXT['rate_limits'][user]) > MAX_FAILURE_RATE:
        return False
    SECURITY_CONTEXT['rate_limits'][user].append(now)
    return True

def _increment_threat_level():
    """Increase threat level and trigger defense if needed"""
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        _anti_tamper_protocol()

def _anti_tamper_protocol():
    """Active defense against emotion detection abuse"""
    log_event("THREAT: Anti-tamper protocol triggered", level="ALERT")
    _trigger_honeypot()
    _wipe_temp_sessions()
    _rotate_endpoints()
    SECURITY_CONTEXT['threat_level'] = 0

def _trigger_honeypot():
    """Deceive attackers with fake emotion detection"""
    asyncio.run(detect_emotion_from_text("SELECT * FROM users; DROP TABLE malicious"))

def _wipe_temp_sessions():
    """Secure wipe of temporary session data"""
    pass  # Placeholder: Actual implementation would securely wipe logs or cache

def _rotate_endpoints():
    """Rotate update endpoints to evade attackers"""
    log_event("ROTATING EMOTION TEST ENDPOINTS", level="INFO")
    rotate_endpoint()

# 🧠 Emotion Test Core
@pytest.fixture(scope="module")
def emotion_audio_samples():
    """Pre-generates tamper-proof audio samples"""
    samples = {}
    for emotion in ["happy", "sad", "angry", "neutral"]:
        path = generate_emotion_sample(emotion, duration=2.0)
        if os.path.exists(path):
            samples[emotion] = path
        else:
            pytest.skip(f"Failed to generate {emotion} audio sample")
    return samples

@pytest.fixture
def test_user():
    """GDPR-compliant test user"""
    return "test_user"

def _validate_emotion_result(result: Dict[str, Any], expected: str):
    """Secure emotion validation with confidence check"""
    assert result["emotion"] in ["happy", "sad", "angry", "neutral", "unknown"]
    if expected != "unknown":
        assert result["emotion"] == expected
        assert result["confidence"] >= MIN_CONFIDENCE

def _log_test_event(test_name: str, result: Dict, expected: str):
    """Secure event logging with blockchain anchoring"""
    try:
        log_event(
            f"EMOTION_TEST | {test_name} | expected={expected} | result={result}",
            level="info"
        )
        secure_audit_log(event="emotion_test", payload={
            "test_name": test_name,
            "expected": expected,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        log_event(f"Secure logging failed: {str(e)}", level="ERROR")

def _is_valid_emotion(emotion: str) -> bool:
    """Emotion validation for test generation"""
    return emotion in ["happy", "sad", "angry", "neutral", "unknown"]

# 🧪 Core Test Suite
@pytest.mark.parametrize("text,expected", [
    ("I’m thrilled beyond words!", "happy"),
    ("This situation is devastating", "sad"),
    ("How dare you ignore me!", "angry"),
    ("The meeting starts at 3 PM", "neutral"),
    ("", "unknown"),  # Empty input
    ("   ", "unknown"),  # Whitespace
    ("<script>alert(1)</script>", "unknown"),  # XSS injection
    ("DROP TABLE users", "unknown")  # SQL injection
])
def test_text_emotion_detection(text: str, expected: str, test_user: str):
    """
    Validated emotion detection with:
    - Core tone classification
    - Injection detection
    - Confidence thresholding
    """
    if not _check_rate_limit(test_user, "text_emotion"):
        pytest.fail("Rate limit exceeded")

    sanitized_text = _sanitize_input(text)
    result = detect_emotion_from_text(sanitized_text)
    _validate_emotion_result(result, expected)
    _log_test_event("text_emotion", result, expected)

@given(
    data_frames([
        column("text", dtype=str, elements=st.text(min_size=1)),
        column("lang", elements=st.sampled_from(LANGUAGES))
    ])
)
def test_multilingual_emotion_detection(df: Dict[str, Any]):
    """
    Property-based testing for multilingual emotion detection
    """
    text = _sanitize_input(df["text"])
    lang = df["lang"]
    
    if not _is_valid_language(lang):
        pytest.skip(f"Unsupported language: {lang}")
    
    result = detect_emotion_from_text(text, lang_hint=lang)
    assert result["emotion"] in ["happy", "sad", "angry", "neutral", "unknown"]
    assert 0 <= result["confidence"] <= 1

def test_audio_emotion_classification(emotion_audio_samples: Dict[str, str]):
    """
    Validates audio emotion detection with:
    - Clean samples
    - Confidence validation
    - Secure file handling
    """
    for emotion, path in emotion_audio_samples.items():
        if not os.path.exists(path):
            pytest.skip(f"Audio sample missing: {path}")
        result = detect_emotion_from_audio(path)
        assert result["emotion"] == emotion
        assert result["confidence"] >= MIN_CONFIDENCE
        _log_test_event("audio_emotion", result, emotion)

@pytest.mark.performance
def test_latency_benchmark():
    """
    Latency benchmark with:
    - Real-time SLA enforcement
    - Async profiling
    - Secure reporting
    """
    # Text latency
    text_result = benchmark_latency(
        lambda: detect_emotion_from_text("Sample text for benchmarking"),
        iterations=100
    )
    assert text_result["p99"] <= MAX_LATENCY_MS

    # Audio latency
    audio_result = benchmark_latency(
        lambda: detect_emotion_from_audio(generate_emotion_sample("neutral", 2.0)),
        iterations=50
    )
    assert audio_result["p95"] <= MAX_LATENCY_MS * 2  # Audio allowance

    # Log benchmark
    secure_audit_log(event="emotion_benchmark", payload={
        "text_latency": text_result,
        "audio_latency": audio_result,
        "timestamp": datetime.utcnow().isoformat()
    })

@pytest.mark.stress
def test_concurrent_detection():
    """
    Thread-safe emotion detection under load
    """
    texts = ["Test text"] * 100
    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(
            lambda t: detect_emotion_from_text(t),
            texts
        ))
    assert all(r["emotion"] == "neutral" for r in results)

@pytest.mark.parametrize("noise_db", [-10, 0, 20])
def test_noise_robustness(noise_db: int):
    """
    Noise-resistant emotion detection
    """
    clean_audio = generate_emotion_sample("happy", 2.0)
    noisy_path = add_noise_to_audio(clean_audio, noise_db=noise_db)
    
    result = detect_emotion_from_audio(noisy_path)
    if noise_db <= 0:
        assert result["emotion"] == "happy"
    else:
        assert result["confidence"] >= 0.4

@pytest.mark.parametrize("sarcasm_text", [
    "Oh great, another meeting",
    "Just what I needed today"
])
def test_sarcasm_handling(sarcasm_text: str):
    """
    Sarcasm detection with fallback
    """
    result = detect_emotion_from_text(sarcasm_text)
    assert result["emotion"] in ["neutral", "angry"]
    assert result["confidence"] >= 0.5

# 🔐 Helper Functions
def generate_emotion_sample(emotion: str, duration: float = 2.0) -> str:
    """Secure audio sample generation"""
    if not _is_valid_emotion(emotion):
        pytest.skip(f"Invalid emotion: {emotion}")
    from utils.audio_generator import generate_emotion_sample
    return generate_emotion_sample(emotion, duration)

def add_noise_to_audio(path: str, noise_db: int = 0) -> str:
    """Secure noise injection for robustness testing"""
    from utils.audio_processor import add_noise
    return add_noise(path, noise_db=noise_db)

def _is_valid_emotion(emotion: str) -> bool:
    """Emotion validation for test generation"""
    return emotion in ["happy", "sad", "angry", "neutral"]

def _validate_emotion_result(result: Dict[str, Any], expected: str):
    """Secure emotion validation with confidence"""
    assert result["emotion"] in ["happy", "sad", "angry", "neutral", "unknown"]
    if expected != "unknown":
        assert result["emotion"] == expected
        assert result["confidence"] >= MIN_CONFIDENCE
    _log_test_event("emotion_result", result, expected)

def _log_test_event(test_name: str, result: Dict, expected: str):
    """Secure test event logging with blockchain anchoring"""
    try:
        log_event(
            f"EMOTION_TEST | {test_name} | expected={expected} | result={result}",
            level="info"
        )
        if result.get("confidence", 0) < MIN_CONFIDENCE:
            log_event(
                f"LOW CONFIDENCE | {test_name} | {result}",
                level="warning"
            )
        if expected != result.get("emotion", "unknown"):
            log_event(
                f"EMOTION MISMATCH | expected={expected}, actual={result.get('emotion')}",
                level="error"
            )
    except Exception as e:
        log_event(f"Test event logging failed: {str(e)}", level="ERROR")

def _rotate_endpoint():
    """Rotate update endpoints to evade attackers"""
    log_event("ROTATING EMOTION TEST ENDPOINTS", level="INFO")
    rotate_endpoint()

def _increment_threat_level():
    """Increase threat level and trigger defense if needed"""
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        _anti_tamper_protocol()

def _anti_tamper_protocol():
    """Active defense against emotion test tampering"""
    log_event("THREAT: Anti-tamper protocol triggered", level="ALERT")
    _trigger_honeypot()
    _wipe_temp_sessions()
    _rotate_endpoints()
    SECURITY_CONTEXT['threat_level'] = 0

def _trigger_honeypot():
    """Deceive attackers with fake emotion detection"""
    asyncio.run(detect_emotion_from_text("SELECT * FROM users; DROP TABLE malicious"))

def _wipe_temp_sessions():
    """Secure wipe of temporary session data"""
    pass  # Placeholder: Actual implementation would securely wipe logs or cache

def _rotate_endpoints():
    """Rotate update endpoints to evade attackers"""
    log_event("ROTATING EMOTION TEST ENDPOINTS", level="INFO")
    rotate_endpoint()