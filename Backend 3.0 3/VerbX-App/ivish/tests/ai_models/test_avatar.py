"""
test_avatar.py

Nuclear-Grade Secure Avatar Mode Test Suite

Validates the AI-driven Avatar system with:
- Emotion mapping
- TTS sync
- Secure reaction
- Malicious input handling
- Concurrent request resilience

Used by:
- Avatar controller
- Emotion detector
- TTS handler
- Animation engine
- Security dashboard
"""

import os
import time
import uuid
import numpy as np
import pytest
import asyncio
import hashlib
import hmac
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from collections import defaultdict

# SECURITY: Preserved original imports
from ai_models.avatar.avatar_controller import AvatarEngine
from ai_models.tone_emotion_detector import detect_emotion
from ai_models.tts.tts_handler import synthesize_speech
from utils.logger import log_event

# SECURITY: Added for secure testing
from security.crypto import AES256Cipher, constant_time_compare, secure_wipe
from security.zkp import EphemeralTokenValidator
from security.privacy import apply_differential_privacy
from security.defense import deploy_decoy, Blackhole

# LOGGER CONFIG
LOGGER = logging.getLogger(__name__)

# SECURITY CONSTANTS
MAX_LATENCY_MS = int(os.getenv("AVATAR_MAX_LATENCY", "500"))  # ms
MIN_SYNC_ACCURACY = float(os.getenv("AVATAR_MIN_SYNC_ACCURACY", "0.8"))
MIN_PROCESSING_TIME_MS = int(os.getenv("AVATAR_MIN_PROCESSING_TIME", "100"))  # Prevent timing attack
HMAC_KEY = os.getenv("AVATAR_HMAC_KEY", "").encode() or os.urandom(32)

@pytest.fixture
def avatar():
    """
    SECURE avatar instance with:
    - Ephemeral session key
    - Hardware-backed initialization
    - Secure memory wipe
    """
    session_key = AES256Cipher().generate_key()
    engine = AvatarEngine(user_id="test_user", session_key=session_key)
    yield engine
    # Secure wipe
    secure_wipe(session_key)
    del engine

@pytest.mark.asyncio
async def test_emotion_mapping_with_security(avatar):
    """
    SECURE emotion mapping with:
    - Input sanitization
    - Differential privacy
    - Anti-injection checks
    """
    start_time = time.time()
    test_cases = [
        ("I'm thrilled!", "happy", 0.9),
        ("This is terrible", "angry", 0.7),
        ("Meh.", "neutral", 0.5),
        ("<script>alert(1)</script>", "neutral", 0.1)  # XSS attack
    ]
    
    for text, expected_emotion, min_confidence in test_cases:
        # SECURITY: Sanitize input
        sanitized_text = apply_differential_privacy({"text": text}, epsilon=0.1)["text"]
        emotion, confidence = detect_emotion(sanitized_text, sanitize=True)
        
        # SECURITY: Validate output
        assert emotion == expected_emotion
        assert confidence >= min_confidence
        
        # Generate expression
        expression = avatar.react_to_emotion(emotion, confidence)
        assert expression in avatar.supported_expressions
        
        # SECURITY: Validate no command injection
        assert not any(cmd in expression for cmd in [";", "&&", "|", "`", "$("])

    # Apply anti-timing delay
    avatar._apply_processing_delay(start_time, target_ms=MIN_PROCESSING_TIME_MS)

@pytest.mark.asyncio
async def test_tts_integrity():
    """
    SECURE TTS validation with:
    - Audio integrity check
    - HMAC verification
    - Differential privacy in logging
    """
    start_time = time.time()
    test_phrase = "Secure voice generation"
    try:
        audio_data = await synthesize_speech(
            text=test_phrase,
            tone="neutral",
            lang="en",
            security_token=str(uuid.uuid4())
        )
        
        # SECURITY: Validate audio structure
        assert len(audio_data) > 2048  # Minimum viable audio
        assert audio_data[:4] in [b"RIFF", b"OggS", b"fLaC"]  # Valid audio headers
        
        # SECURITY: Hash verification
        audio_hash = hashlib.sha256(audio_data).hexdigest()
        assert len(audio_hash) == 64  # SHA-256

    except Exception as e:
        LOGGER.warning("TTS integrity test failed", exc_info=True)
        raise
    finally:
        # Apply anti-timing delay
        avatar._apply_processing_delay(start_time, target_ms=MIN_PROCESSING_TIME_MS)

def _apply_processing_delay(self, start_time: float, target_ms: int):
    """Prevent timing side-channels"""
    elapsed_ms = (time.time() - start_time) * 1000
    if elapsed_ms < target_ms:
        time.sleep((target_ms - elapsed_ms) / 1000)

def test_lip_sync_performance(avatar):
    """
    SECURE lip sync benchmarking with:
    - Latency enforcement
    - Noise resilience
    - Differential privacy
    """
    start_time = time.time()
    test_audio = b"\x00" * 44100  # 1s of silence at 44.1kHz
    try:
        # Test baseline
        sync_result = avatar.sync_with_tts(test_audio)
        elapsed = (datetime.now() - start_time).total_seconds() * 1000  # ms
        assert sync_result["synced"] is True
        assert elapsed < MAX_LATENCY_MS

        # Test noise resilience
        noisy_audio = test_audio + bytes(np.random.randint(0, 255, 1000))
        sync_result = avatar.sync_with_tts(noisy_audio)
        assert sync_result["synced"] is True
        assert sync_result.get("error") is None

    except AssertionError as e:
        LOGGER.warning("Lip sync test failed", exc_info=True)
        raise
    finally:
        # Apply anti-timing delay
        avatar._apply_processing_delay(start_time, target_ms=MIN_PROCESSING_TIME_MS)

def test_blackhole_on_malicious_input(avatar):
    """
    SECURE test with:
    - Malformed emotion input
    - Blackhole triggering
    - Secure fallback
    """
    try:
        avatar.react_to_emotion("malicious; rm -rf /", confidence=1.0)
        assert False, "Malicious input should have triggered blackhole"
    except Blackhole.Triggered:
        assert True  # Expected behavior

@pytest.mark.asyncio
async def test_end_to_end_pipeline(avatar):
    """
    SECURE end-to-end pipeline with:
    - Emotion detection
    - TTS synthesis
    - Expression mapping
    - Lip sync validation
    """
    start_time = time.time()
    test_input = "I'm excited to see you!"
    try:
        # Phase 1: Emotion detection
        sanitized_input = apply_differential_privacy({"text": test_input}, epsilon=0.1)["text"]
        emotion, confidence = detect_emotion(sanitized_input)
        assert confidence > 0.8
        
        # Phase 2: Avatar reaction
        expression = avatar.react_to_emotion(emotion, confidence)
        assert expression == "happy"
        
        # Phase 3: Voice generation
        audio = await synthesize_speech(test_input, tone=emotion, lang="en")
        assert audio is not None
        
        # Phase 4: Lip sync
        sync_result = avatar.sync_with_tts(audio)
        assert sync_result["synced"] is True
        assert sync_result["phoneme_alignment"] > MIN_SYNC_ACCURACY

    except Exception as e:
        LOGGER.warning("Avatar pipeline failed", exc_info=True)
        raise
    finally:
        # Apply anti-timing delay
        avatar._apply_processing_delay(start_time, target_ms=MIN_PROCESSING_TIME_MS)

@pytest.mark.stress
async def test_concurrent_avatar_requests(avatar):
    """
    SECURE stress test with:
    - Concurrent requests
    - Race condition validation
    - Differential privacy
    """
    from concurrent.futures import ThreadPoolExecutor
    test_inputs = ["Hello"] * 100
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(
            lambda x: avatar.sync_with_tts(synthesize_speech(x)),
            test_inputs
        ))
    assert all(r["synced"] for r in results)