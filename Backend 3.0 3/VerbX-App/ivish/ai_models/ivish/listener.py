import threading
import time
import numpy as np
import sounddevice as sd
import os
import hashlib
import json
from typing import Optional, Dict, Any, List

# Corrected Imports based on Project Architecture
from backend.app.utils.logger import log_event
from ai_models.whisper.whisper_handler import transcribe_audio
from ai_models.emotion.emotion_handler import EmotionEngine
from realtime.buffers.speech_buffer import SecureAudioBuffer
from realtime.socketio.manager import send_audio_chunk
from backend.app.services.diagnostic_service import mic_health_check
from backend.app.utils.security import validate_audio_chunk
from security.firewall import AudioFirewall
from security.intrusion_prevention.counter_response import trigger_blackhole
from security.intrusion_prevention.isolation_engine import rotate_endpoint
from security.blockchain.blockchain_utils import log_to_blockchain
from backend.app.middlewares.latency_monitor import enforce_realtime
from backend.app.services.ivish_service import create_session, end_session
from ai_models.slang.slang_cleaner import SlangCleaner


class IvishListener:
    """
    Core audio listener for the VerbX app.
    Securely captures, validates, and processes audio for Ivish.
    """

    def __init__(self):
        # 📚 System Flags
        self.samplerate = int(os.getenv("AUDIO_SAMPLERATE", 16000))
        self.channels = int(os.getenv("AUDIO_CHANNELS", 1))
        self.listening = False
        self.audio_buffer = SecureAudioBuffer()
        self.thread = None
        self.session_id = None
        self._firewall = AudioFirewall(device_id=os.getenv("DEVICE_FINGERPRINT", "default"))
        self._last_wake = 0
        self._last_attack = 0

        # 🧠 AI Engines
        self.emotion_engine = EmotionEngine()
        self.slang_cleaner = SlangCleaner()

        # 🔐 Secure Device Initialization
        try:
            sd.check_input_settings(device=None, channels=self.channels, samplerate=self.samplerate)
        except sd.PortAudioError as e:
            log_event(f"MIC SECURITY ALERT: {str(e)}", level="ALARM")
            self._trigger_failover()

    @enforce_realtime(50)
    def start_listener(self):
        """Secure thread launch with watchdog and session."""
        if self.listening:
            return
        self.session_id = create_session()
        self.listening = True
        self.thread = threading.Thread(
            target=self._listen_loop,
            name="SecureListenerThread",
            daemon=True
        )
        self.thread.start()
        log_event("Listener: Secure audio pipeline ONLINE", session_id=self.session_id)

    def stop_listener(self):
        """Graceful shutdown with buffer wipe and session end."""
        self.listening = False
        if self.thread:
            self.thread.join(timeout=1.0)
        self.audio_buffer.wipe()
        end_session(self.session_id)
        log_event("Listener: OFF (Memory sanitized)", session_id=self.session_id)

    def _listen_loop(self):
        """Zero-trust audio processing loop."""
        def callback(indata, frames, time_info, status):
            if status or not validate_audio_chunk(indata):
                log_event("Audio tampering blocked", level="ALERT", session_id=self.session_id)
                self._trigger_failover()
                return
            audio_chunk = np.copy(indata)
            
            # Use the audio firewall's scan method to check for wake word and other audio security
            if self._firewall.scan(audio_chunk):
                self._handle_wake_trigger(audio_chunk)

        with sd.InputStream(
            callback=callback,
            samplerate=self.samplerate,
            channels=self.channels,
            blocksize=2048,
            dtype='float32'
        ):
            while self.listening:
                time.sleep(0.05)
                self._check_health()

    def _handle_wake_trigger(self, chunk):
        """Secure wake word handling with session tracking."""
        now = time.time()
        if now - self._last_wake < 2.0:
            return
        
        # This is a placeholder for a sophisticated model-based wake word detector
        if self._firewall.detect_wake_word(chunk):
            self._last_wake = now
            threading.Thread(
                target=self._post_wake_protocol,
                daemon=True
            ).start()

    def _post_wake_protocol(self):
        """Isolated post-wake execution with session isolation."""
        try:
            self.buffer_audio_after_wake()
        except Exception as e:
            log_event(f"Post-wake crash: {str(e)}", level="ERROR", session_id=self.session_id)
            self._trigger_failover()

    def buffer_audio_after_wake(self, duration_sec=5):
        """Secure buffering with auto-wipe on failure."""
        try:
            audio_data = sd.rec(
                int(self.samplerate * duration_sec),
                samplerate=self.samplerate,
                channels=self.channels,
                dtype='float32'
            )
            if not sd.wait(timeout=duration_sec + 1):
                raise TimeoutError("Audio capture stalled")
            if validate_audio_chunk(audio_data):
                self.audio_buffer.store(audio_data)
                self.dispatch_audio(audio_data)
            else:
                raise ValueError("Invalid audio signature")
        except Exception as e:
            log_event(f"Buffer failure: {str(e)}", level="ERROR", session_id=self.session_id)
            self.audio_buffer.wipe()

    def dispatch_audio(self, audio_chunk):
        """Zero-trust audio routing with blockchain audit."""
        try:
            # 🔐 Cryptographic Hashing
            checksum = self._generate_checksum(audio_chunk)
            
            # 🧠 AI-powered Processing
            text = transcribe_audio(audio_chunk, local_model=bool(os.getenv("OFFLINE_MODE", False)), checksum=checksum)
            
            # 🗣️ Slang and Code-Mixed Language Cleaning
            text = self.slang_cleaner.clean(text)
            
            # 🎭 Emotion Detection
            emotion_result = self.emotion_engine.detect_emotion_from_text(text)
            
            # 🚨 Emotion Risk Detection
            if emotion_result.get('risk_level', 0) > 0.8:
                log_event(f"CRITICAL TONE: {emotion_result}", level="ALARM", session_id=self.session_id)
                self._trigger_auto_wipe()

            send_audio_chunk(text, emotion_result, session_id=self.session_id)
            log_to_blockchain("audio_dispatch", {"text": text, "emotion": emotion_result}, session_id=self.session_id)

        except Exception as e:
            log_event(f"Dispatch crash: {str(e)}", level="ERROR", session_id=self.session_id)
            self._trigger_failover()

    def _check_health(self):
        """Continuous defense monitoring."""
        if not mic_health_check() or not self._firewall.is_secure():
            log_event("HEALTH CHECK FAILED", level="ALARM", session_id=self.session_id)
            self._trigger_failover()

    # 🔐 Security Protocols
    def _trigger_failover(self):
        """Graceful degradation to backup mic."""
        self.stop_listener()
        # This module does not exist in the provided file structure, so it's a placeholder
        # from backup.mic_failover import activate_backup
        # activate_backup()

    def _trigger_honeypot(self):
        """Deceive attackers with fake audio."""
        now = time.time()
        if now - self._last_attack < 60:
            return
        self._last_attack = now
        fake_audio = np.random.rand(self.samplerate, 1).astype('float32') * 0.01
        self.dispatch_audio(fake_audio)

    def _trigger_auto_wipe(self):
        """Secure wipe on risk detection."""
        self.audio_buffer.wipe()
        end_session(self.session_id)
        rotate_endpoint()
        log_event("Auto-wipe and endpoint rotation triggered", session_id=self.session_id)

    def _generate_checksum(self, audio: np.ndarray) -> str:
        """Tamper-proof audio hashing using SHA256."""
        # Use a more robust hashing method for real-world scenarios
        return hashlib.sha256(audio.tobytes()).hexdigest()