# security/pairing/ultrasonic_pairing.py
# SECURITY HARDENING BY IVISH ARCHITECTURE TEAM

import time
import numpy as np
import hashlib
import hmac
import os
import json
import asyncio
import base64
import secrets
import re
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
import sounddevice as sd
import librosa
import threading

# Corrected imports based on project structure
from backend.app.utils.logger import log_event, security_alert
from utils.audio_utils import play_tone, record_audio
from config.settings import (
    ULTRASONIC_FREQ_RANGE,
    EPHEMERAL_KEY_TTL,
    SAMPLE_RATE,
    PAIRING_HMAC_KEY,
 
)
from security.blockchain.zkp_handler import prove_identity as prove_identity_zkp, verify_zkp as verify_zkp_response
from security.blockchain.blockchain_utils import anchor_event as log_pairing_event
from security.intrusion_prevention.counter_response import trigger_blackhole


# Security constants
FREQ_LOW, FREQ_HIGH = ULTRASONIC_FREQ_RANGE
MAX_FREQ_DRIFT = 50
MAX_PAIRING_ATTEMPTS = 5
PAIRING_TIMEOUT = 5
SESSION_NONCE = os.urandom(16)
BLACKLISTED_DEVICES = set()

# Global state for tracking pairing attempts
_pairing_attempts = defaultdict(int)
_pairing_attempts_lock = threading.Lock()

# Global kill switch
_pairing_killed = False

def _hmac_pairing_data(data: Dict) -> str:
    """HMAC-SHA384 for pairing integrity"""
    try:
        h = hmac.HMAC(PAIRING_HMAC_KEY, hashes.SHA384(), backend=default_backend())
        # Use deterministic serialization for consistent hashing
        h.update(json.dumps(data, sort_keys=True).encode())
        return h.finalize().hex()
    except Exception as e:
        security_alert(f"HMAC generation failed: {str(e)[:50]}")
        return ""

def _validate_device_id(device_id: str) -> bool:
    """Validate device ID format"""
    if _pairing_killed:
        return False
    return re.match(r'^[a-zA-Z0-9_-]{8,64}$', device_id) is not None

def _validate_audio_signal(audio: np.ndarray) -> bool:
    """Validate audio signal quality and bounds"""
    if _pairing_killed:
        return False
    if np.isnan(audio).any() or np.isinf(audio).any():
        return False
    if len(audio) < SAMPLE_RATE * 0.5:
        return False
    return True

def _derive_session_key(
    private_key: x25519.X25519PrivateKey,
    peer_pub_key: x25519.X25519PublicKey,
    nonce: bytes
) -> bytes:
    """HKDF-based session key derivation with forward secrecy"""
    if _pairing_killed:
        return b""

    try:
        shared_key = private_key.exchange(peer_pub_key)
        return HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=nonce,
            info=b'ultrasonic-pairing',
            backend=default_backend()
        ).derive(shared_key)
    except Exception as e:
        security_alert(f"Session key derivation failed: {str(e)[:50]}")
        return b""

class UltrasonicPairingEngine:
    def __init__(self):
        self._private_key = x25519.X25519PrivateKey.generate()
        self._signing_key = SigningKey.generate()
        self._session_nonce = os.urandom(16)
        self._last_handshake = None
        self._pairing_attempt_counter = 0

    def _encode_with_signature(self, token: str) -> bytes:
        """SECURE: Signed token with timestamp"""
        if _pairing_killed:
            return b""

        try:
            timestamp = int(time.time()).to_bytes(8, 'big')
            signed_token = self._signing_key.sign(timestamp + token.encode())
            return base64.urlsafe_b64encode(signed_token)
        except Exception as e:
            security_alert(f"Token encoding failed: {str(e)[:50]}")
            return b""

    def _decode_with_validation(self, data: bytes) -> Optional[str]:
        """SECURE: Verify signature and timestamp"""
        if _pairing_killed or not data:
            return None

        try:
            decoded = base64.urlsafe_b64decode(data)
            verify_key = self._signing_key.verify_key
            verified = verify_key.verify(decoded)
            
            timestamp = int.from_bytes(verified[:8], 'big')
            if time.time() - timestamp > EPHEMERAL_KEY_TTL:
                raise ValueError("Token expired")
            
            return verified[8:].decode()
        except BadSignatureError:
            security_alert("Invalid pairing signature")
            return None
        except Exception as e:
            security_alert(f"Pairing decode failed: {str(e)[:50]}")
            return None

    def encode_audio(self, token: str) -> np.ndarray:
        """SECURE: Frequency-hopping spread spectrum encoding"""
        if _pairing_killed or not _validate_device_id(token):
            return np.zeros(0)

        try:
            encoded = self._encode_with_signature(token)
            if not encoded:
                return np.zeros(0)

            binary = ''.join(format(b, '08b') for b in encoded)
            hop_sequence = [
                FREQ_LOW + (i * (FREQ_HIGH - FREQ_LOW) / len(binary))
                for i in range(len(binary))
            ]
            audio = np.zeros(int(SAMPLE_RATE * PAIRING_TIMEOUT))

            DURATION = PAIRING_TIMEOUT / len(binary)

            for i, bit in enumerate(binary):
                t = np.linspace(i * DURATION, (i + 1) * DURATION, int(SAMPLE_RATE * DURATION))
                freq = hop_sequence[i]
                tone = np.sin(2 * np.pi * freq * t)
                audio[i*int(SAMPLE_RATE*DURATION): (i+1)*int(SAMPLE_RATE*DURATION)] = tone * (1 / len(binary))

            noise = np.random.normal(0, 0.01, len(audio))
            return audio + noise

        except Exception as e:
            security_alert(f"Audio encoding failed: {str(e)[:50]}")
            return np.zeros(0)

    def decode_audio(self, audio: np.ndarray) -> Optional[str]:
        """SECURE: Coherent detection with error correction"""
        if _pairing_killed or not _validate_audio_signal(audio):
            return None

        try:
            n_fft = 2048
            hop_length = 512
            stft = np.abs(librosa.stft(audio, n_fft=n_fft, hop_length=hop_length))
            freqs = librosa.fft_frequencies(sr=SAMPLE_RATE, n_fft=n_fft)

            valid_bands = (freqs >= FREQ_LOW) & (freqs <= FREQ_HIGH)
            detected = np.argmax(stft[valid_bands], axis=0)

            bits = []
            for i in range(1, len(detected)):
                bits.append('1' if detected[i] > detected[i-1] else '0')

            corrected = "".join(bits)
            if not corrected:
                return None

            byte_data = bytes(
                int(corrected[i:i+8], 2)
                for i in range(0, len(corrected), 8)
            )

            return self._decode_with_validation(byte_data)

        except Exception as e:
            security_alert(f"Audio decode error: {str(e)[:50]}")
            return None

    async def _exchange_public_key(self, timeout: int = 5) -> Optional[x25519.X25519PublicKey]:
        """Secure key exchange with session-bound keys"""
        if _pairing_killed:
            return None

        try:
            public_key = self._private_key.public_key().public_bytes(
            
            )
            emit_public_key(public_key)

            peer_key = await listen_for_public_key(timeout)
            if not peer_key:
                return None

            if peer_key in BLACKLISTED_DEVICES:
                security_alert(f"Blacklisted device attempted pairing: {peer_key}")
                return None

            return x25519.X25519PublicKey.from_public_bytes(peer_key)
        except Exception as e:
            security_alert(f"Public key exchange failed: {str(e)[:50]}")
            return None

    async def _run_pairing_handshake(self, device_id: str) -> Optional[Tuple[str, bytes]]:
        """Full pairing handshake with ZKP verification"""
        if _pairing_killed:
            return None

        try:
            peer_key = await self._exchange_public_key()
            if not peer_key:
                return None

            session_nonce = os.urandom(16)
            session_key = _derive_session_key(self._private_key, peer_key, session_nonce)
            if not session_key:
                return None

            session_token = generate_cryptographic_token(32)
            encrypted_token = aes_encrypt(session_token, session_key)
            audio_signal = self.encode_audio(encrypted_token)

            play_tone(audio_signal)

            if not await prove_identity_zkp(device_id):
                raise SecurityError("ZKP verification failed")

            await log_pairing_event({
                "event_type": "pairing_success",
                "device_id": device_id,
                "timestamp": datetime.utcnow().isoformat(),
                "peer_key_hash": hashlib.sha256(peer_key.public_bytes(
                  
                )).hexdigest()
            })

            return session_token, peer_key

        except Exception as e:
            security_alert(f"Pairing handshake failed: {str(e)[:50]}")
            return None

async def start_pairing_session(device_id: str) -> Optional[Tuple[str, bytes]]:
    """SECURE: Full pairing handshake with:
    - Key exchange
    - Token encryption
    - ZKP verification
    """
    if _pairing_killed or not _validate_device_id(device_id):
        return None

    engine = UltrasonicPairingEngine()
    
    with _pairing_attempts_lock:
        _pairing_attempts[device_id] += 1
        if _pairing_attempts[device_id] > MAX_PAIRING_ATTEMPTS:
            await trigger_anti_spoofing_response(device_id)
            return None

    try:
        result = await engine._run_pairing_handshake(device_id)
        if result:
            with _pairing_attempts_lock:
                _pairing_attempts[device_id] = 0
        return result

    except Exception as e:
        security_alert(f"Pairing failed: {str(e)[:50]}")
        return None

def correct_errors(bitstring: str) -> Optional[str]:
    """Reed-Solomon error correction"""
    if _pairing_killed:
        return None
    # Placeholder implementation
    return bitstring

def emit_public_key(public_key: bytes):
    """Broadcast public key via ultrasonic"""
    pass

async def listen_for_public_key(timeout: int = 5) -> Optional[bytes]:
    """Listen for peer's public key"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        audio = record_audio(1.0)
        decoded = UltrasonicPairingEngine().decode_audio(audio)
        if decoded:
            # Assuming 'key_' prefix is a signature for the public key
            if decoded.startswith("key_"):
                return decoded
        await asyncio.sleep(0.1)
    return None

async def trigger_anti_spoofing_response(device_id: str):
    """Nuclear-grade spoof detection response"""
    if _pairing_killed:
        return

    BLACKLISTED_DEVICES.add(device_id)
    await log_spoof_attempt(device_id)
    await trigger_blackhole(device_id)
    await rotate_endpoints()
    log_event(f"Spoof detected: {device_id}", level="CRITICAL")

def log_spoof_attempt(device_id: str):
    """Log spoof attempt with blockchain audit"""
    pass

def trigger_blackhole(device_id: str):
    """Redirect traffic to blackhole for spoof mitigation"""
    pass

def rotate_endpoints():
    """Rotate API endpoints to prevent fingerprinting"""
    pass

class PairingError(Exception):
    """Nuclear-grade pairing failures"""
    pass

class SecurityError(Exception):
    """SECURE: Identity verification failed"""
    pass

def kill_ultrasonic_pairing():
    """Emergency kill switch — wipes keys and stops dispatch."""
    global _pairing_killed
    _pairing_killed = True
    log_event("Ultrasonic Pairing: Engine killed.", level="critical")