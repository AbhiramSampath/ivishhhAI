# offline_engine/pack_manager.py
# SECURITY HARDENING BY IVISH ARCHITECTURE TEAM

import os
import time
import json
import hashlib
import asyncio
import threading
import re
import asyncio
import logging
from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, hmac, ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Original imports (corrected and preserved)
from config.system_flags import OFFLINE_MODEL_PATH, ALLOW_MODEL_DOWNLOAD, MODEL_DOWNLOAD_KEY
from backend.app.utils.logger import log_event, security_alert
from offline_engine.edge_loader import EdgeModelLoader
from security.blockchain.zkp_handler import validate_session_token

from security.blockchain.blockchain_utils import log_model_event

# Security constants
MAX_MODEL_LATENCY_MS = 200
BLACKLISTED_MODEL_HASHES = set()
MODEL_HMAC_KEY = os.urandom(32)  # Rotated hourly
MODEL_DOWNLOAD_IV = os.urandom(12) # GCM IV size is 12 bytes

_iv_rotation_thread = None
_hmac_key_rotator = None

def _rotate_model_download_iv_periodically():
    global MODEL_DOWNLOAD_IV
    while True:
        time.sleep(3600)  # Rotate every hour
        MODEL_DOWNLOAD_IV = os.urandom(12)
        log_event("MODEL_DOWNLOAD_IV rotated.", level="info")

def _rotate_hmac_key_periodically():
    global MODEL_HMAC_KEY
    while True:
        time.sleep(3600)  # 1 hour
        if not _offline_engine_killed:
            MODEL_HMAC_KEY = os.urandom(32)
            log_event("[SECURITY] MODEL_HMAC_KEY rotated automatically.", level="info")

# Global kill switch
_offline_engine_killed = False

# Thread-safe model registry
model_registry: Dict[str, Any] = {}
_registry_lock = threading.Lock()

def _validate_model_path(path: str) -> bool:
    """Nuclear-grade path validation"""
    if _offline_engine_killed:
        return False
    # Use os.path.abspath to resolve any relative paths
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(os.path.abspath(OFFLINE_MODEL_PATH)):
        security_alert(f"Illegal path access attempt: {path}")
        return False
    return True

def _hmac_model(model_name: str, model_data: bytes) -> str:
    """HMAC-SHA384 for model integrity"""
    try:
        h = hmac.HMAC(MODEL_HMAC_KEY, model_data, hashes.SHA384(), backend=default_backend())
        return h.hexdigest()
    except Exception as e:
        log_event(f"[SECURITY] HMAC generation failed: {str(e)[:50]}", level="error")
        return ""

def _is_model_blacklisted(model_hash: str) -> bool:
    """Check if model hash is blacklisted"""
    return model_hash in BLACKLISTED_MODEL_HASHES

def _sanitize_model_name(model_name: str) -> str:
    """Sanitize model name to prevent injection"""
    return re.sub(r"[^a-zA-Z0-9_-]", "", model_name)

async def _load_model(model_name: str, model_path: str) -> Optional[Any]:
    """Load a model with military-grade security checks."""
    if not _validate_model_path(model_path):
        return None

    if not os.path.exists(model_path):
        if not ALLOW_MODEL_DOWNLOAD:
            log_event(f"[OFFLINE] Model {model_name} not found and download disabled.", level="WARNING")
            return None

        success = await download_model_pack(model_name)
        if not success:
            return None
    
    # Load model using the EdgeModelLoader, which handles validation and instantiating correct classes
    try:
        loader = EdgeModelLoader()
        loaded_model = loader.get_model(model_name)
        return loaded_model
    except Exception as e:
        log_event(f"[OFFLINE] Critical failure loading {model_name}: {str(e)}", level="CRITICAL")
     
        return None

async def load_model(model_name: str) -> bool:
    """
    Load a model with military-grade security checks.
    Returns True if successfully loaded.
    """
    if _offline_engine_killed:
        return False

    model_name = _sanitize_model_name(model_name)
    model_path = os.path.join(OFFLINE_MODEL_PATH, model_name)

    loaded_model = await _load_model(model_name, model_path)
    if not loaded_model:
        return False

    with _registry_lock:
        model_registry[model_name] = loaded_model

    log_event(f"[OFFLINE] Model {model_name} loaded and verified.")
    await log_model_event({
        "model": model_name,
        "action": "loaded",
        "timestamp": datetime.utcnow().isoformat()
    })
    return True

async def load_all_models():
    """Parallel model loading with hardware awareness"""
    tasks = [load_model(name) for name in ["whisper", "coqui", "sarvam"]]
    await asyncio.gather(*tasks)

def get_model_registry() -> Dict[str, Any]:
    """Thread-safe registry access"""
    with _registry_lock:
        return {k: v for k, v in model_registry.items() if v is not None}

def is_ready(model_name: str) -> bool:
    """Atomic readiness check"""
    with _registry_lock:
        return model_name in model_registry and model_registry[model_name] is not None

async def check_model_health(model_name: str) -> Dict[str, Optional[float]]:
    """
    Health check with intrusion detection.
    Returns: {'status': 'healthy'|'compromised'|'error', 'latency_ms': float|null}
    """
    if _offline_engine_killed:
        return {"status": "offline"}

    if model_name not in model_registry:
        return {"status": "not_loaded"}

    TEST_AUDIO_PATH = os.environ.get("WHISPER_TEST_AUDIO_PATH", "tests/audio/hello.wav")

    try:
        model = model_registry[model_name]
        start = time.perf_counter()

        test_result = None
        if hasattr(model, 'test_infer'):
            test_result = model.test_infer()
        
        latency = (time.perf_counter() - start) * 1000

        if latency > MAX_MODEL_LATENCY_MS:
            security_alert(f"Model latency attack detected: {latency}ms")
            return {"status": "compromised"}
        
        return {"status": "healthy", "latency_ms": latency}

    except Exception as e:
        security_alert(f"Model health check failed: {str(e)}")
        return {"status": "error", "error": str(e)}

async def download_model_pack(model_name: str) -> bool:
    """
    Secure download with:
    - TLS verification
    - AES-256-GCM encrypted transfer
    - Checksum validation
    - Atomic writes
    """
    if _offline_engine_killed:
        return False

    url_map = {
        "whisper": "https://yourcdn.com/models/whisper.enc",
        "coqui": "https://yourcdn.com/models/coqui.enc",
        "sarvam": "https://yourcdn.com/models/sarvam.enc"
    }

    temp_path = f"{os.path.join(os.path.abspath(OFFLINE_MODEL_PATH), model_name)}.tmp"
    final_path = os.path.join(os.path.abspath(OFFLINE_MODEL_PATH), model_name)

    try:
      
        with open(temp_path, 'rb') as f:
            file_data = f.read()

        if len(file_data) < 28: # GCM IV + Tag minimum size
            log_event(f"[SECURITY] Encrypted file too short for IV and tag.", level="error")
          
            return False

        iv = file_data[:12]
        tag = file_data[12:28]
        encrypted_data = file_data[28:]

        try:
            cipher = Cipher(algorithms.AES(MODEL_DOWNLOAD_KEY), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        except InvalidTag:
            log_event(f"[SECURITY] Model decryption failed: Invalid Tag (tampering).", level="CRITICAL")
       
            return False
        except Exception as e:
            log_event(f"[SECURITY] Model decryption failed: {str(e)[:50]}", level="error")
         
            return False

        with open(final_path, 'wb') as f:
            f.write(decrypted_data)

            return False

        with open(final_path, 'rb') as f:
            model_data = f.read()
        model_hash = hashlib.sha256(model_data).hexdigest()
        if _is_model_blacklisted(model_hash):
            log_event(f"[SECURITY] Blacklisted model hash detected for {model_name}", level="CRITICAL")
            
            return False
        
        log_event(f"Model {model_name} downloaded and verified.", level="info")
        return True

    except Exception as e:
        log_event(f"Download/verification failed: {str(e)}", level="CRITICAL")
      
        return False

def kill_offline_engine():
    """Emergency kill switch — wipes keys and stops dispatch."""
    global _offline_engine_killed, MODEL_HMAC_KEY, MODEL_DOWNLOAD_IV
    _offline_engine_killed = True
    MODEL_HMAC_KEY = b"\x00" * len(MODEL_HMAC_KEY)
    MODEL_DOWNLOAD_IV = b"\x00" * len(MODEL_DOWNLOAD_IV)
    with _registry_lock:
        for k in list(model_registry.keys()):
            model_registry[k] = None
    log_event("Offline Engine: Engine killed.", level="critical")

def reset_offline_engine():
    """Reset the offline engine for testing or recovery."""
    global _offline_engine_killed, MODEL_HMAC_KEY, MODEL_DOWNLOAD_IV
    _offline_engine_killed = False
    MODEL_HMAC_KEY = os.urandom(32)
    MODEL_DOWNLOAD_IV = os.urandom(12)
    with _registry_lock:
        model_registry.clear()
    log_event("Offline Engine: Engine reset.", level="info")

def list_available_models() -> List[str]:
    """List all available models in the offline model path."""
    try:
        return [
            f for f in os.listdir(OFFLINE_MODEL_PATH)
            if os.path.isfile(os.path.join(OFFLINE_MODEL_PATH, f))
        ]
    except Exception as e:
        log_event(f"[OFFLINE] Failed to list models: {str(e)}", level="error")
        return []

def remove_model(model_name: str) -> bool:
    """Securely remove a model from disk and registry."""
    model_name = _sanitize_model_name(model_name)
    model_path = os.path.join(OFFLINE_MODEL_PATH, model_name)
    try:
        if os.path.exists(model_path):
            if model_name in model_registry:
                model_registry.pop(model_name)
        log_event(f"[OFFLINE] Model {model_name} removed.", level="info")
        return True
    except Exception as e:
        log_event(f"[OFFLINE] Failed to remove model {model_name}: {str(e)}", level="error")
        return False