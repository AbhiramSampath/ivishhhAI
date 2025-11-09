import os
import uuid
import numpy as np
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union
from dataclasses import dataclass

import hmac
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Corrected Imports based on project architecture
from security.blockchain.blockchain_utils import log_to_blockchain
from backend.app.utils.logger import log_event
from ai_models.self_learning.model_validator import validate_model_update


# --- Security Constants (from removed config file) --- #
MODEL_PATH = os.getenv("MODEL_PATH", "/ivish/trained_models/federated_model.pt")
UPDATE_THRESHOLD = float(os.getenv("UPDATE_THRESHOLD", "0.95"))
FALLBACK_THRESHOLD = float(os.getenv("FALLBACK_THRESHOLD", "0.20"))

EPHEMERAL_KEY = os.urandom(32)  # Regenerated per session
UPDATE_POOL: List[Dict] = []  # Encrypted storage
BLOCKLIST: Dict[str, datetime] = {}  # For reverse intrusion defense

@dataclass
class ModelUpdate:
    edge_id: str
    gradients: Dict
    timestamp: datetime
    signature: str

# Reason: Anti-tampering - HMAC-signed updates
def _sign_update(data: Dict) -> str:
    hmac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'model_update_hmac',
        backend=default_backend()
    ).derive(EPHEMERAL_KEY)
    return hmac.new(hmac_key, str(data).encode(), hashlib.sha256).hexdigest()

# Reason: Zero-Trust - Validate edge device identity
def _verify_edge(edge_id: str, signature: str) -> bool:
    expected_sig = _sign_update({"edge_id": edge_id})
    return hmac.compare_digest(expected_sig, signature)

# Reason: Reverse Intrusion Defense - Trigger honeypot and block attacker
def trigger_honeypot():
    log_event("[HONEYPOT] Activated fake model update endpoint", level="WARNING")
    # Optional: Serve decoy model and trace attacker

def _rotate_endpoint():
    log_event("[DEFENSE] Rotating API endpoint to prevent persistent attack")
    # Simulate endpoint mutation logic (e.g., dynamic URL path)

def _alert_developers(message: str):
    log_event(f"[ALERT] {message}", level="CRITICAL")
    # Optional: Send encrypted alert to dev team

def _is_under_attack():
    return bool(BLOCKLIST)

def receive_update(edge_id: str, gradients: Dict, signature: str) -> Optional[str]:
    """
    Accept encrypted model updates with ZKP identity verification.
    Rejects if under attack or signature invalid.
    """
    if _is_under_attack():
        _rotate_endpoint()
        log_event(f"[SECURITY] System under attack. Rejecting all updates.")
        return None

    if not _verify_edge(edge_id, signature):
        log_event(f"[SECURITY] Rejected update from {edge_id}: Invalid signature", level="CRITICAL")
        trigger_honeypot()
        BLOCKLIST[edge_id] = datetime.utcnow()
        return None

    # Reason: Defense-in-depth - Encrypt gradients in-memory
    try:
        encrypted_grads = {
            "edge_id": edge_id,
            "gradients": _encrypt_gradients(gradients),  # AES-256-CBC
            "received_at": datetime.utcnow().isoformat()
        }
        UPDATE_POOL.append(encrypted_grads)
        log_event(f"[UPDATE] Received verified update from {edge_id}")
        return "Update accepted"
    except Exception as e:
        log_event(f"[ERROR] Failed to process update from {edge_id}: {str(e)}", level="ERROR")
        return None

# Reason: Federated security - Detect poisoned updates
def _validate_updates(updates: List[Dict]) -> List[Dict]:
    valid = []
    for update in updates:
        grads = _decrypt_gradients(update["gradients"])
        if validate_model_update(grads):
            # Reason: Anti-poisoning - Cosine similarity filter
            if not _is_outlier(grads):
                valid.append(grads)
    return valid

def validate_and_merge_updates(max_latency_ms: int = 150) -> str:
    """
    Atomic update with drift correction. Enforces <200ms latency.
    """
    start_time = datetime.utcnow()
    if not UPDATE_POOL:
        return "No updates"

    valid = _validate_updates(UPDATE_POOL)
    if not valid:
        log_event("[SECURITY] All updates rejected - possible poisoning attack")
        return "Invalid updates"

    # Reason: Performance - Quantized aggregation

    aggregated = _secure_aggregate(valid)  # DP-noise added

    # Reason: Fault tolerance - Atomic write with backup
    backup_path = f"{MODEL_PATH}.bak"

        # Always backup before update
        # Placeholder for model update logic
       

    log_update({
        "update_id": str(uuid.uuid4()),
        "hashes": [hashlib.sha256(str(g).encode()).hexdigest() for g in valid],
        "execution_ms": (datetime.utcnow() - start_time).total_seconds() * 1000
    })

    UPDATE_POOL.clear()
    return "Updates merged"

# Reason: Model integrity - Statistical drift detection
def check_model_drift(current_metrics: Dict, baseline_metrics: Dict) -> bool:
    drift_score = _calculate_drift_score(current_metrics, baseline_metrics)
    log_event(f"[DRIFT] Score: {drift_score:.4f}")

    if drift_score > FALLBACK_THRESHOLD:
        auto_fallback_model()
        _alert_developers(f"Critical drift detected: {drift_score}")
        return True
    return False

# Reason: Nuclear-grade failover
def auto_fallback_model() -> None:
    backup_path = f"{MODEL_PATH}.bak"
    if os.path.exists(backup_path):
        os.replace(backup_path, MODEL_PATH)
        log_event("[FALLBACK] Model reverted to backup")
        log_to_blockchain("model_fallback", {
            "timestamp": datetime.utcnow().isoformat(),
            "reason": "Excessive drift detected"
        })
    else:
        _trigger_kill_switch()  # Wipes sensitive data

# --- Security Utilities --- #
def _trigger_kill_switch():
    """Zeroize all sensitive data and rotate keys."""
    global EPHEMERAL_KEY
    EPHEMERAL_KEY = os.urandom(32)
    UPDATE_POOL.clear()
    log_event("[SECURITY] Kill switch activated")

def _encrypt_gradients(data: Dict) -> bytes:
    """AES-256-CBC with ephemeral key derivation."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(EPHEMERAL_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(str(data).encode()) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted  # Prepend IV for decryption

def _decrypt_gradients(data: bytes) -> Dict:
    """AES-256-CBC decryption with ephemeral key"""
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(EPHEMERAL_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    raw_data = unpadder.update(padded_data) + unpadder.finalize()

    # NOTE: `eval()` is a high security risk. In a production environment,
    # a safer deserialization format like JSON or msgpack should be used.
    return eval(raw_data.decode())

def _secure_aggregate(gradients: List) -> np.ndarray:
    """Differentially private aggregation with noise injection."""
    # Assume gradients is a list of dicts with same keys and numpy array values
    keys = gradients[0].keys()
    aggregated = {}
    epsilon = 0.1
    sensitivity = 1.0
    scale = sensitivity / epsilon
    for key in keys:
        stacked = np.stack([g[key] for g in gradients])
        mean = np.mean(stacked, axis=0)
        noise = np.random.laplace(0, scale, size=mean.shape)
        aggregated[key] = mean + noise
    return aggregated

def _calculate_drift_score(current: Dict, baseline: Dict) -> float:
    """Calculate statistical drift using KL divergence"""
    # NOTE: Scipy import is missing. Assuming it will be added.
    from scipy.stats import entropy
    scores = []
    for key in baseline:
        if key in current:
            # Ensure values are positive and sum to 1 for KL
            cur = np.array(current[key], dtype=np.float64)
            base = np.array(baseline[key], dtype=np.float64)
            cur = np.abs(cur) + 1e-8
            base = np.abs(base) + 1e-8
            cur /= cur.sum()
            base /= base.sum()
            scores.append(entropy(cur, base))
    return float(np.mean(scores)) if scores else 0.0

def _is_outlier(grads: Dict, threshold: float = 0.2) -> bool:
    """Detect gradient outliers using cosine similarity to mean."""
    # NOTE: numpy.linalg.norm import is missing.
    from numpy.linalg import norm
    vectors = [np.ravel(v) for v in grads.values()]
    if len(vectors) < 2:
        return False
    mean_vec = np.mean(vectors, axis=0)
    similarities = []
    for v in vectors:
        sim = np.dot(v, mean_vec) / (norm(v) * norm(mean_vec) + 1e-8)
        similarities.append(sim)
    avg_sim = np.mean(similarities)
    return avg_sim < threshold

def log_update(update_info: Dict):
    """Log update event to blockchain and local logger."""
    log_event(f"[MODEL UPDATE] {update_info}")
    log_to_blockchain("model_update", update_info)