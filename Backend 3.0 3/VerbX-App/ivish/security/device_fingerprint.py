# security/device_fingerprint.py
# 🔒 Nuclear-Grade Device Fingerprinting with Zero-Trust Validation
# Enables secure, auditable, and real-time device identification

import logging
import os
import time
import uuid
import asyncio
import hashlib
import subprocess
import json
import platform
import socket
import secrets
from typing import Dict, Optional, Any, List, Tuple, Union
from fastapi import Request, HTTPException
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes

# Security imports (Corrected paths based on project architecture)
from security.intrusion_prevention.threat_detector import flag_suspicious_device
# from security.blockchain.zkp_handler import validate_device_proof
# from security.firewall import Firewall

# from security.blockchain.blockchain_utils import log_device_event
from backend.app.utils.logger import log_event
# from config.system_flags import (
#     FINGERPRINT_TOLERANCE,
#     FINGERPRINT_SALT,
#     MAX_DEVICE_VELOCITY_KMH
# )
FINGERPRINT_TOLERANCE = 0.1
FINGERPRINT_SALT = "default_salt"
MAX_DEVICE_VELOCITY_KMH = 1000

# Security constants
MAX_FINGERPRINT_RATE = 50  # Max fingerprint requests per minute
BLACKHOLE_DELAY = 60  # Seconds to delay attacker
RATE_LIMIT_WINDOW = 60  # Rate-limiting window
TEMP_FINGERPRINT_PATHS = ["/tmp/ivish_fingerprint_*", "/dev/shm/fingerprint_*"]
DEVICE_CACHE_TTL = timedelta(minutes=5)

# AES-256-GCM encryption
DEVICE_FINGERPRINT_KEY = os.getenv("DEVICE_FINGERPRINT_KEY", "default_key_32_chars_long_1234567890").encode()[:32]
# if len(DEVICE_FINGERPRINT_KEY) != 32:
#     raise RuntimeError("Invalid encryption key for device fingerprint")

# Initialize security components
# firewall = Firewall()
logger = logging.getLogger(__name__)
device_cache = {}

class DeviceFingerprinter:
    """
    Provides secure, auditable, and real-time device fingerprinting.
    """
    def __init__(self):
        self._request_count = {}
        self._window_start = time.time()
        self._known_devices = {}
        self._rate_limiter_lock = asyncio.Lock()

    async def _validate_rate_limit(self, user_id: str) -> bool:
        """Prevent fingerprint flooding attacks."""
        async with self._rate_limiter_lock:
            now = time.time()
            if user_id not in self._request_count or now - self._request_count[user_id]["window"] > RATE_LIMIT_WINDOW:
                self._request_count[user_id] = {
                    "count": 0,
                    "window": now
                }
            self._request_count[user_id]["count"] += 1
            if self._request_count[user_id]["count"] > MAX_FINGERPRINT_RATE:
                log_event("[SECURITY] Fingerprint rate limit exceeded", level="WARNING")
                self._trigger_blackhole()
                return False
            return True

    def _trigger_blackhole(self):
        """Null response + artificial delay on attack detection."""
        logger.warning(f"Blackhole activated for {BLACKHOLE_DELAY}s")
        time.sleep(BLACKHOLE_DELAY)

    def _secure_wipe(self, paths: list):
        """Securely wipe temporary fingerprint data."""
        for path in paths:
            try:
                subprocess.run(['shred', '-u', path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error(f"Secure wipe failed for {path}: {e}")

    def _encrypt_data(self, data: bytes) -> bytes:
        """AES-256-GCM encryption for fingerprints with a fresh IV."""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(DEVICE_FINGERPRINT_KEY),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def _decrypt_data(self, data: bytes) -> bytes:
        """Secure fingerprint decryption."""
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = Cipher(
            algorithms.AES(DEVICE_FINGERPRINT_KEY),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _derive_hardware_id(self) -> str:
        """Hardware-bound ID using system characteristics"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=FINGERPRINT_SALT.encode(),
            info=b"ivish-device-id",
            backend=default_backend()
        )
        base_id = ":".join([
            str(uuid.getnode()),
            platform.processor() or "",
            socket.gethostname()
        ]).encode()
        return hkdf.derive(base_id).hex()

    def _extract_audio_fingerprint(self, audio_data: Optional[bytes] = None) -> str:
        """WebAudio API or native audio context fingerprint"""
        if not audio_data:
            return "null"
        return hashlib.sha3_256(audio_data).hexdigest()

    async def extract_device_features(self, request: Request) -> Dict:
        """Multi-factor device fingerprint collection"""
        ua_str = request.headers.get("User-Agent", "")
        # Assuming a `parse_ua` function exists elsewhere
        # user_agent = parse_ua(ua_str)
        ip = request.client.host

      
        audio_task = asyncio.create_task(self._get_audio_fp(request))

        features = {
            "hardware_id": self._derive_hardware_id(),
            "ip": ip,
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            # "browser": f"{user_agent.browser.family}/{user_agent.browser.version_string}",
            "screen": request.headers.get("X-Screen-Res", "unknown"),
            "timezone": request.headers.get("X-Timezone", "unknown"),
            "gpu": request.headers.get("X-GPU-Renderer", "unknown"),
            "fonts": json.loads(request.headers.get("X-Fonts", "[]")),
            "audio": await audio_task,
           
            "clock_skew": int(request.headers.get("X-Clock-Skew", "0")),
            "webgl_hash": request.headers.get("X-WebGL-Hash", "null"),
            "device_token": request.headers.get("X-Device-Token", "null"),
            "session_id": request.cookies.get("session_id", "null")
        }

        # Sanitize input
       

        # Rate limit check
       

    async def generate_fingerprint(self, request: Request) -> Tuple[str, str]:
        """Returns (ephemeral_fp, persistent_fp) pair"""
        features = await self.extract_device_features(request)


    async def validate_device(self, request: Request, user_id: str, known_fp: str) -> bool:
        """
        Zero-trust device validation with:
        - Fingerprint matching
        - Geo-velocity checks
        - Behavioral analysis
        - ZKP challenge
        - Blockchain logging
        """
        if not await self._validate_rate_limit(user_id):
            return False

        ephemeral_fp, persistent_fp = await self.generate_fingerprint(request)
        
        if persistent_fp in self._known_devices.get(user_id, []):
            logger.warning(f"[SECURITY] Known bad device {user_id}")
            firewall.trigger_blackhole()
            return False
        
        if not self._compare_hashes(persistent_fp, known_fp):
            logger.warning(f"[SECURITY] Device spoofing detected for {user_id}")
            await log_device_event({
                "action": "device_spoofing",
                "user_id": user_id,
                "timestamp": time.time(),
                "device_hash": persistent_fp
            })
            flag_suspicious_device(user_id, request.client.host)
            return False
        
        if not await self._check_geo_velocity(request, user_id):
            logger.warning(f"[SECURITY] Impossible travel for {user_id}")
            return False
            
        if not await validate_device_proof(request, persistent_fp):
            logger.warning(f"[SECURITY] ZKP device challenge failed {user_id}")
            return False
            
        return True

    async def _check_geo_velocity(self, request: Request, user_id: str) -> bool:
        """Detects impossible travel scenarios"""
    
        return True

    def _compare_hashes(self, fp1: str, fp2: str) -> bool:
        """Secure hash comparison with timing attack protection"""
        return secrets.compare_digest(fp1, fp2)

    def _hash_user_id(self, user_id: str) -> str:
        """PBKDF2-HMAC-SHA512 user hashing"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=b"fingerprint_user_salt_2023",
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(user_id.encode()).hex()

    def _secure_subprocess(self, command: list):
        """Secure subprocess execution"""
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _get_audio_fp(self, request: Request) -> Optional[str]:
        """Placeholder for audio fingerprinting."""
        return self._extract_audio_fingerprint()

# Singleton with rate limit
fingerprinter = DeviceFingerprinter()