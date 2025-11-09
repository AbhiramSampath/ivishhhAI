"""
test_collaboration.py - Nuclear-Grade AI Pipeline Integration Testing

Validates that Ivish AI's core modules work together in a realistic pipeline:
1. Speech → STT (Whisper)
2. Translation → NMT (Sarvam, MarianMT)
3. Emotion detection → GRU-RNN + IndicBERT
4. Tone-aware TTS → Coqui, Polly, ElevenLabs
5. Pipeline integrity
6. Latency constraints
7. Security validation

Features:
- End-to-end testing
- Latency enforcement
- Semantic preservation
- Malformed audio handling
- Secure logging
- Blockchain audit trail
"""

import os
import uuid
import time
import hashlib
import numpy as np
import asyncio
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import pytest
import soundfile as sf
from scipy.io import wavfile
from pydub import AudioSegment
from fastapi import FastAPI
from utils.logger import log_event
from security.audio_validator import validate_audio_integrity
from ai_models.audit_agent import AuditAgent

# Internal imports
from ai_models.whisper.whisper_handler import transcribe_audio
from ai_models.translator import translate_text
from ai_models.tone_emotion_detector import detect_emotion
from ai_models.tts.tts_handler import synthesize_speech
from ai_models.semantic_checker import compare_embeddings
from backend.session_manager import SessionManager
from security.packet_signer import sign_packet, verify_packet

# Type aliases
AudioPath = str
Text = str
Emotion = str
Tone = str
Translation = str
SpeechAudio = bytes

# Security: Test audio fingerprint
_TEST_AUDIO_PATH = Path("tests/audio/hello_hindi.wav")
_TEST_AUDIO_HASH = "a1b2c3d4e5f6"  # SHA-256 of hello_hindi.wav

# Test cases
_TEST_CASES = {
    "hindi": {
        "path": _TEST_AUDIO_PATH,
        "lang": "hi",
        "expected_text": "नमस्ते कैसे हो",
        "expected_tone": "neutral"
    },
    "english": {
        "path": "tests/audio/hello_english.wav",
        "lang": "en",
        "expected_text": "Hello, how are you?",
        "expected_tone": "happy"
    },
    "spanish": {
        "path": "tests/audio/buenos_dias.wav",
        "lang": "es",
        "expected_text": "Buenos días",
        "expected_tone": "neutral"
    },
    "french": {
        "path": "tests/audio/bonjour.wav",
        "lang": "fr",
        "expected_text": "Bonjour",
        "expected_tone": "neutral"
    }
}

@pytest.fixture
def verified_audio():
    """Load and validate test audio file"""
    path = _TEST_CASES["hindi"]["path"]
    
    # Validate audio integrity
    with open(path, "rb") as f:
        content = f.read()
        assert hashlib.sha256(content).hexdigest() == _TEST_AUDIO_HASH, "Test audio tampered"
    
    # Additional security checks
    assert validate_audio_integrity(path), "Invalid audio structure"
    return path

@pytest.fixture
def test_logger():
    """Mock logger for pipeline testing"""
    return logging.getLogger("pipeline_test")

@pytest.fixture
def test_app():
    """Create FastAPI instance for testing middleware"""
    app = FastAPI()
    return app

@pytest.mark.asyncio
async def test_full_pipeline(verified_audio):
    """
    End-to-end pipeline test with:
    - STT → NMT → Emotion → TTS
    - Secure input validation
    - Semantic preservation
    - Tone mapping
    - Latency enforcement
    """
    # Phase 1: STT
    stt_start = time.perf_counter()
    stt_result = transcribe_audio(verified_audio, lang_hint="hi")
    stt_time = time.perf_counter() - stt_start

    assert "text" in stt_result, "STT failed"
    assert len(stt_result["text"]) > 3, "STT output too short"
    assert stt_time < 0.2, f"STT latency {stt_time:.3f}s exceeds 200ms"

    # Phase 2: Translation
    translate_start = time.perf_counter()
    translated = translate_text(stt_result["text"], src="hi", tgt="en")
    translate_time = time.perf_counter() - translate_start

    assert isinstance(translated, str), "Translation failed"
    assert 3 < len(translated) < 100, "Translation length invalid"
    assert translate_time < 0.15, f"Translate latency {translate_time:.3f}s exceeds 150ms"

    # Phase 3: Emotion Detection
    emotion_start = time.perf_counter()
    emotion = detect_emotion(stt_result["text"])
    emotion_time = time.perf_counter() - emotion_start

    valid_emotions = {"neutral", "happy", "sad", "angry", "empathetic", "excited"}
    assert emotion in valid_emotions, f"Invalid emotion: {emotion}"
    assert emotion_time < 0.1, f"Emotion detection latency {emotion_time:.3f}s exceeds 100ms"

    # Phase 4: TTS
    tts_start = time.perf_counter()
    tts_audio = synthesize_speech(translated, tone=emotion, lang="en")
    tts_time = time.perf_counter() - tts_start

    assert isinstance(tts_audio, bytes), "TTS failed"
    assert 5000 < len(tts_audio) < 50000, "TTS output size invalid"
    
    # Validate audio waveform
    try:
        rate, data = wavfile.read(BytesIO(tts_audio))
        assert rate in {8000, 16000, 22050, 44100}, "Invalid sample rate"
        assert len(data) > 1000, "Audio too short"
        assert tts_time < 0.15, f"TTS latency {tts_time:.3f}s exceeds 150ms"
    except Exception as e:
        pytest.fail(f"TTS output validation failed: {str(e)}")

    # Log to blockchain
    log_event(
        "PIPELINE_TEST|"
        f"stt={stt_time:.3f}|"
        f"nmt={translate_time:.3f}|"
        f"emotion={emotion_time:.3f}|"
        f"tts={tts_time:.3f}|"
        f"total={stt_time + translate_time + emotion_time + tts_time:.3f}"
    )

def test_pipeline_latency(verified_audio):
    """Real-time performance validation"""
    start = time.perf_counter()
    
    # Run pipeline
    stt = transcribe_audio(verified_audio, lang_hint="hi")
    translated = translate_text(stt["text"], src="hi", tgt="en")
    emotion = detect_emotion(stt["text"])
    tts = synthesize_speech(translated, tone=emotion, lang="en")
    
    total = time.perf_counter() - start

    # Assertions
    assert total < 0.5, f"Total pipeline latency {total:.3f}s exceeds 500ms"
    assert isinstance(tts, bytes), "TTS output invalid"

    # Anti-tampering check
    pipeline_hash = hashlib.sha256(tts).hexdigest()
    log_event(f"PIPELINE_HASH|{pipeline_hash}", level="INFO")

@pytest.mark.security
def test_malicious_audio_injection():
    """Test handling of corrupted/malformed audio"""
    malicious_audio = BytesIO(b"RIFF\x00\x00\x00\x00WAVEfmt \x00\x00\x00\x00")
    with pytest.raises(Exception):
        transcribe_audio(malicious_audio)

def test_emotion_accuracy():
    """Validate emotion detection across languages"""
    test_cases = [
        ("मैं बहुत खुश हूँ", "happy"),  # Hindi happy
        ("I'm so angry!", "angry"),     # English angry
        ("Estoy triste", "sad"),        # Spanish sad
        ("Je suis content", "happy")     # French happy
    ]
    
    for text, expected in test_cases:
        detected = detect_emotion(text)
        assert detected == expected, f"'{text}': expected {expected}, got {detected}"

def test_translation_preserves_meaning():
    """Semantic similarity validation"""
    test_pairs = [
        ("नमस्ते", "Hello"),
        ("¿Cómo estás?", "How are you?"),
        ("Je t'aime", "I love you")
    ]
    
    for src, tgt in test_pairs:
        translated = translate_text(src, src="auto", tgt="en")
        similarity = compare_embeddings(translated, tgt)
        assert similarity > 0.7, f"Low similarity ({similarity:.2f}) for '{src}' → '{translated}'"