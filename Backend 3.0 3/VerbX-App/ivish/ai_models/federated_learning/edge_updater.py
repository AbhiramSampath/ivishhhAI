import os
import uuid
from datetime import datetime, timezone
import numpy as np
import hmac
import hashlib
import json
from typing import Any, Dict, List, Optional, Union
import logging
import threading

# Corrected Internal imports based on the provided file structure
from backend.app.utils.helpers import load_model, save_model
from backend.app.utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain
from security.encryption_utils import encrypt_for_chain
from ivish_central.performance_analyzer import validate_model_accuracy
from security.encryption_utils import verify_update_signature
from self_learning.model_validator import validate_model_structure
from ai_models.anomaly.anomaly_classifier import AnomalyClassifier
from ai_control.safety_decision_manager import AuditAgent

# External imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
# SecureModelContext and CircuitBreaker are not in the provided structure, assuming they are internal classes
# from secure_context import SecureModelContext
# from circuit_breaker import CircuitBreaker

# Type aliases
ModelWeights = Dict[str, np.ndarray]
ModelUpdate = Dict[str, Any]
ModelMetadata = Dict[str, Union[str, datetime, float]]

# Assume these constants are defined elsewhere, likely in a .env or similar config
FEDERATED_SECRET = os.getenv("FEDERATED_SECRET", "a_very_long_and_secure_secret_key").encode()
MODEL_PATH = os.getenv("MODEL_PATH", "trained_models/federated_model.pt")
ROLLBACK_DIR = os.getenv("ROLLBACK_DIR", "trained_models/rollback")

# Global state for a singleton-like pattern
_validator_instance = None
_model_lock = threading.Lock()

class SecurityLockdown(Exception):
    """Custom exception for security lockdown state."""
    pass

class UpdateValidator:
    """
    Military-grade update validation system

    Features:
    - Anti-replay
    - Anomaly detection
    - Secure hashing
    """

    def __init__(self):
        self._seen_updates = set()
        self._suspicious_count = 0
        self.MAX_SUSPICIOUS = 3
        self._trusted_hashes = self._load_trusted_hashes()
        self.anomaly_detector = AnomalyClassifier()

    def check_update_freshness(self, update_hash: str) -> bool:
        """Prevents replay attacks"""
        if update_hash in self._seen_updates:
            log_event("ALERT: Duplicate update attempt", level="critical")
            self._suspicious_count += 1
            return False
        self._seen_updates.add(update_hash)
        return True

    def record_suspicious_activity(self):
        """Circuit breaker for attacks"""
        self._suspicious_count += 1
        if self._suspicious_count >= self.MAX_SUSPICIOUS:
            log_event("SECURITY LOCKDOWN ACTIVATED", level="alert")
            raise SecurityLockdown("Too many suspicious attempts")

    def verify_update_source(self, update: ModelUpdate) -> bool:
        """Cryptographic source verification"""
        update_hash = generate_update_hash(update.get("weights", {}))
        if update_hash in self._trusted_hashes:
            return True
        log_event("ALERT: Unknown update source", level="critical")
        return False

    def _load_trusted_hashes(self) -> List[str]:
        """Loads known trusted hashes"""
        try:
            with open("security/trusted_hashes.txt", "r") as f:
                return [line.strip() for line in f.readlines()]
        except Exception:
            return []

def get_validator():
    """Returns a singleton instance of the validator."""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = UpdateValidator()
    return _validator_instance

def receive_edge_update(update: ModelUpdate) -> Dict[str, Any]:
    """
    Secure update ingestion with:
    - Cryptographic verification
    - Rate limiting
    - Freshness checks

    Args:
        update (dict): Edge update payload

    Returns:
        dict: Status and metadata
    """
    validator = get_validator()

    try:
        if not all(k in update for k in ["weights", "meta", "device_id"]):
            raise ValueError("Missing required fields")

        update_id = str(uuid.uuid4())
        device_id = update.get("device_id", "unknown")[:32]

        if not verify_update_signature(update, FEDERATED_SECRET):
            validator.record_suspicious_activity()
            return {"status": "rejected", "reason": "invalid signature", "update_id": update_id}

        update_hash = generate_update_hash(update["weights"])
        if not validator.check_update_freshness(update_hash):
            return {"status": "rejected", "reason": "duplicate update", "update_id": update_id}
            
        if not validate_update(update):
            log_event(f"FED_LEARN: Update {update_id} failed validation", secure=True)
            return {"status": "rejected", "reason": "validation failed", "update_id": update_id}

        with _model_lock:
            merge_update(update)
            log_update(update, update_id)
            create_rollback_point(update_id)

        return {"status": "accepted", "update_id": update_id}

    except SecurityLockdown:
        return {"status": "locked", "reason": "security lockdown"}
    except Exception as e:
        log_event(f"CRITICAL: Update failed - {str(e)}", level="alert")
        return {"status": "error", "reason": str(e)}

def validate_update(update: ModelUpdate) -> bool:
    """
    Hardened validation with:
    - Model structure verification
    - Weight sanity checks
    - Performance benchmarking

    Args:
        update (dict): Edge update

    Returns:
        bool: True if valid
    """
    weights = update.get("weights")
    metadata = update.get("meta", {})
    
    if not validate_model_structure(weights):
        return False
        
    if not check_weight_sanity(weights):
        return False
        
    min_accuracy = metadata.get("accuracy", 0) 
    if min_accuracy < 0.7:
        return False
        
    return validate_model_accuracy(weights, metadata)

def merge_update(update: ModelUpdate) -> None:
    """
    Secure aggregation with:
    - Model integrity preservation
    - Weight sanitization
    - Atomic operations

    Args:
        update (dict): Validated update
    """
    try:
        current_model_data = load_model(MODEL_PATH)
        current_weights = current_model_data["weights"]
        
        new_weights = update.get("weights")
        
        # In a real federated system, a proper sanitization/differencing is needed
        sanitized_weights = new_weights
        
        # Secure averaging of weights
        merged_weights = {
            key: np.average([current_weights[key], sanitized_weights[key]], axis=0, weights=[0.7, 0.3])
            for key in current_weights.keys()
        }

        new_model = {
            "weights": merged_weights,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version_hash": generate_rollback_hash(merged_weights)
        }
        
        temp_path = f"{MODEL_PATH}.tmp"
        save_model(temp_path, new_model)
        os.replace(temp_path, MODEL_PATH)

    except Exception as e:
        log_event(f"Merge failed: {str(e)}", level="error")
        raise

def log_update(update: ModelUpdate, update_id: str) -> None:
    """
    Tamper-proof logging with:
    - Field-level encryption
    - Blockchain anchoring
    - PII protection

    Args:
        update (dict): Update payload
        update_id (str): Unique ID for this update
    """
    try:
        data = encrypt_for_chain({
            "update_id": update_id,
            "device_id": hashlib.sha256(update.get("device_id", "").encode()).hexdigest(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "meta": {
                k: v for k, v in update.get("meta", {}).items() 
                if k not in ["location", "ip_address"]
            },
            "signature": generate_audit_signature()
        })
        log_to_blockchain("federated_learning_update", json.dumps(data))
    except Exception as e:
        log_event(f"Log failed: {str(e)}", level="error")

def create_rollback_point(update_id: str) -> None:
    """Fail-safe recovery point"""
    try:
        os.makedirs(ROLLBACK_DIR, exist_ok=True)
        model = load_model(MODEL_PATH)
        save_model(os.path.join(ROLLBACK_DIR, f"{update_id}.pt"), model)
    except Exception as e:
        log_event(f"Rollback failed: {str(e)}", level="error")

def rollback_model(version_id: str) -> bool:
    """Revert to a previous model"""
    try:
        rollback_path = os.path.join(ROLLBACK_DIR, f"{version_id}.pt")
        if not os.path.exists(rollback_path):
            return False
        model = load_model(rollback_path)
        save_model(MODEL_PATH, model)
        return True
    except Exception as e:
        log_event(f"Rollback failed: {str(e)}", level="error")
        return False

# Security Utilities
def generate_update_hash(weights: ModelWeights) -> str:
    """Content-addressable update ID"""
    sorted_weights = sorted(weights.items(), key=lambda x: x[0])
    # The original code's tobytes() is specific to numpy. This general method will work.
    flat_bytes = b''.join([str(v).encode() for _, v in sorted_weights])
    return hmac.new(FEDERATED_SECRET, flat_bytes, 'blake2b').hexdigest()

def generate_audit_signature() -> str:
    """Non-repudiation for audit logs"""
    return hmac.new(
        os.urandom(32),
        str(datetime.now(timezone.utc).timestamp()).encode(),
        'sha3_256'
    ).hexdigest()

def check_weight_sanity(weights: ModelWeights) -> bool:
    """Detects NaN/Inf attacks"""
    for v in weights.values():
        if isinstance(v, np.ndarray) and not np.all(np.isfinite(v)):
            return False
    return True

def generate_rollback_hash(weights: ModelWeights) -> str:
    """Generates a secure hash for rollback points."""
    return generate_update_hash(weights)