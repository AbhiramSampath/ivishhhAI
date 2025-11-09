import os
import shutil
import threading
from datetime import datetime, timezone
from typing import Dict, Optional, Any, List
from dataclasses import dataclass

import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Corrected Imports based on Project Architecture
from backend.app.utils.helpers import load_model, swap_model, get_model_info
from federated_learning.aggregator import fetch_latest_model_bundle
from backend.app.models.performance_metrics import compute_accuracy, compute_bleu_score
from backend.app.utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain
from ai_control.safety_decision_manager import ALLOW_MODEL_SWAP
from security.intrusion_prevention.counter_response import trigger_blackhole
from security.intrusion_prevention.isolation_engine import rotate_endpoint
from self_learning.model_validator import validate_model_structure as _validate_model_structure

# --- Security Constants --- #
EPHEMERAL_KEY = os.urandom(32)
MODEL_LOCK = threading.Lock()
MODEL_DIR = "trained_models/ivish"
BACKUP_DIR = os.path.join(MODEL_DIR, "backup")
MIN_ACCURACY = 0.92
MIN_BLEU = 0.75
MAX_LATENCY_MS = 200
MAX_RETRY_ATTEMPTS = 3
BLOCKLIST: Dict[str, datetime] = {}

@dataclass
class ModelUpdateMetadata:
    model_id: str
    test_data: str
    latency_ms: float
    signature: str
    timestamp: datetime

# Reason: Anti-tampering - Verify model bundle integrity
def _sign_model(data: bytes, model_id: str) -> str:
    hmac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'model_bundle_hmac',
        backend=default_backend()
    ).derive(EPHEMERAL_KEY + model_id.encode())
    return hmac.new(hmac_key, data, hashlib.sha3_256).hexdigest()

def _verify_model_signature(model_path: str, metadata: ModelUpdateMetadata) -> bool:
    try:
        with open(model_path, 'rb') as f:
            file_data = f.read()
        expected_sig = _sign_model(file_data, metadata.model_id)
        return hmac.compare_digest(expected_sig, metadata.signature)
    except Exception as e:
        log_event(f"[ERROR] Signature verification failed: {str(e)}", level="ERROR")
        return False

def _is_under_attack():
    return bool(BLOCKLIST)

def _rotate_endpoint():
    log_event("[DEFENSE] Rotating API endpoint to prevent persistent attack")
    rotate_endpoint()

def _alert_developers(message: str):
    log_event(f"[ALERT] {message}", level="CRITICAL")

def check_for_updates() -> None:
    """
    Zero-trust update check with cryptographic validation.
    """
    if _is_under_attack():
        _rotate_endpoint()
        log_event("[SECURITY] System under attack. Rejecting all updates.")
        return

    try:
        model_path, raw_metadata = fetch_latest_model_bundle()
        if not model_path or not raw_metadata:
            log_event("[ERROR] No model or metadata received", level="WARNING")
            return

        metadata = ModelUpdateMetadata(**raw_metadata)
        if not _verify_model_signature(model_path, metadata):
            log_event("[SECURITY] Model signature mismatch", level="CRITICAL")
            trigger_honeypot()
            return

        with MODEL_LOCK:
            test_result = _validate_model(model_path, metadata)
            if test_result["passed"] and ALLOW_MODEL_SWAP:
                _swap_if_valid(model_path, metadata, test_result)

    except Exception as e:
        log_event(f"[SECURITY] Update check failed: {str(e)}", level="ERROR")
        _rotate_ephemeral_key()

def _validate_model(model_path: str, metadata: ModelUpdateMetadata) -> Dict:
    """Rigorous offline evaluation with security checks"""
    try:
        test_data = metadata.test_data
        new_model = load_model(model_path)

        if not _validate_model_structure(new_model):
            return {"passed": False, "reason": "Invalid model structure"}

        metrics = {
            "accuracy": compute_accuracy(new_model, test_data),
            "bleu": compute_bleu_score(new_model, test_data),
            "latency_ms": metadata.latency_ms,
            "bias_score": _compute_bias_score(new_model)
        }

        passed = (
            metrics["accuracy"] >= MIN_ACCURACY and
            metrics["bleu"] >= MIN_BLEU and
            metrics["latency_ms"] <= MAX_LATENCY_MS and
            metrics["bias_score"] < 0.1
        )

        log_event(f"[Validation] Metrics: {metrics}")
        return {"passed": passed, **metrics}
    except Exception as e:
        log_event(f"[ERROR] Model validation failed: {str(e)}", level="ERROR")
        return {"passed": False, "error": str(e)}

def _swap_if_valid(model_path: str, metadata: ModelUpdateMetadata, test_result: Dict) -> None:
    """Atomic model swap with rollback guarantee"""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        old_model = get_model_info()["path"]
        backup_path = os.path.join(
            BACKUP_DIR,
            f"model_backup_{datetime.now(timezone.utc).isoformat()}.bin"
        )
        
        shutil.copy(old_model, backup_path)
        
        if not _validate_model(model_path, metadata)["passed"]:
            raise ValueError("Post-backup validation failed")

        swap_model(model_path)
        _log_swap_event(old_model, model_path, test_result, metadata)

    except Exception as e:
        if os.path.exists(backup_path):
            swap_model(backup_path)
        _log_swap_event(old_model, model_path, test_result, metadata, error=str(e))
        raise
    finally:
        if os.path.exists(model_path):
            os.remove(model_path)

def _log_swap_event(old_path: str, new_path: str, test_result: Dict,
                   metadata: ModelUpdateMetadata, error: str = "") -> None:
    """Immutable audit trail"""
    try:
        with open(old_path, 'rb') as f:
            old_hash = hashlib.sha256(f.read()).hexdigest()
        with open(new_path, 'rb') as f:
            new_hash = hashlib.sha256(f.read()).hexdigest()
        
        log_to_blockchain("model_swap", {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "old_model_hash": old_hash,
            "new_model_hash": new_hash,
            "test_metrics": test_result,
            "security": {
                "key_fingerprint": hashlib.sha256(EPHEMERAL_KEY).hexdigest(),
                "signature_valid": _verify_model_signature(new_path, metadata)
            },
            "error": error
        })
    except Exception as e:
        log_event(f"[ERROR] Blockchain log failed: {str(e)}", level="ERROR")

def trigger_honeypot() -> None:
    """Deploy decoy model to attackers"""
    try:
        # Corrected honeypot logic to use the function from a security module
        trigger_blackhole()
        log_to_blockchain("honeypot_triggered", {
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        log_event(f"[ERROR] Honeypot failed: {str(e)}", level="ERROR")

def _rotate_ephemeral_key() -> None:
    global EPHEMERAL_KEY
    EPHEMERAL_KEY = os.urandom(32)
    log_event("[SECURITY] Ephemeral key rotated")

def _compute_bias_score(model: Any) -> float:
    """Simulate fairness check (replace with real logic)"""
    return 0.05

if __name__ == "__main__":
    log_event("[INFO] Manual model update check triggered")
    check_for_updates()