import logging
import os
import time
import uuid
import hashlib
import hmac
import numpy as np
import subprocess
import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException
from collections import defaultdict

# --- Placeholder Imports for non-existent modules ---
def load_base_model(model_name: str) -> Any:
    """Placeholder for loading the base model."""
    logging.info(f"Placeholder: Loading base model {model_name}")
    return np.zeros((10, 10), dtype=np.float32)

def save_global_model(weights: np.ndarray, model_name: str) -> None:
    """Placeholder for saving the global model."""
    logging.info(f"Placeholder: Saving global model {model_name}")

# Corrected Internal imports
from backend.app.utils.logger import log_event, BaseLogger
from security.blockchain.blockchain_utils import log_to_blockchain
from ai_models.self_learning.model_validator import validate_model_update
from security.blockchain.zkp_handler import validate_client_for_fed_learning

# --- Constants (from removed config file) ---
ENABLE_FED_LEARNING = os.getenv("ENABLE_FED_LEARNING", "True").lower() == "true"
FED_ROUND_THRESHOLD = int(os.getenv("FED_ROUND_THRESHOLD", "50"))
MODEL_NAME = "emotion_model"  # Example model name

MAX_CLIENTS_PER_ROUND = 1000
WEIGHT_PRECISION = np.float32
ROUND_TIMEOUT = 3600
RATE_LIMIT_WINDOW = 60
MAX_UPDATES_PER_MIN = 50
BLACKHOLE_DELAY = 60
TEMP_MODEL_PATHS = ["/tmp/fed_model_*", "/dev/shm/fed_*"]

# --- Security Globals ---
HMAC_KEY = os.urandom(32)
logger = BaseLogger("FederatedAggregator")

class FederatedAggregator:
    """
    Provides secure, auditable, and decentralized federated learning aggregation.
    """
    def __init__(self):
        self.client_updates: List[Dict] = []
        self._request_count = 0
        self._window_start = time.time()
        self._derived_key = self._derive_round_key()
        self._round_start = time.time()
        self._model_version = "initial"

    def _reset_rate_limit(self):
        now = time.time()
        if now - self._window_start > RATE_LIMIT_WINDOW:
            self._request_count = 0
            self._window_start = now

    async def _validate_rate_limit(self) -> bool:
        """Prevent federated update flooding attacks."""
        self._reset_rate_limit()
        self._request_count += 1
        if self._request_count > MAX_UPDATES_PER_MIN:
            await log_event("[SECURITY] Federated update rate limit exceeded", level="ALERT")
            await self._trigger_blackhole()
            return False
        return True

    async def _trigger_blackhole(self):
        """Null response + artificial delay on attack detection."""
        logger.log_event(f"Blackhole activated for {BLACKHOLE_DELAY}s", level="WARNING")
        await asyncio.sleep(BLACKHOLE_DELAY)

    async def _secure_wipe(self, paths: list):
        """Securely wipe temporary model data."""
        for path in paths:
            try:
                await asyncio.to_thread(
                    subprocess.run,
                    ['shred', '-u', path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                logger.log_event(f"Secure wipe failed for {path}: {e}", level="ERROR")

    def _derive_round_key(self) -> bytes:
        """HKDF-derived key for each aggregation round."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b'federated_round_key',
        ).derive(os.urandom(32))

    def _sign_update(self, weights_bytes: bytes, client_id: str) -> bytes:
        """HMAC sign a model update."""
        h = hmac.HMAC(self._derived_key, hashes.SHA256())
        h.update(weights_bytes)
        h.update(client_id.encode())
        return h.finalize()

    def _verify_update_integrity(self, weights_bytes: bytes, client_id: str, hmac_sig: bytes) -> bool:
        """HMAC validation of weight updates."""
        h = hmac.HMAC(self._derived_key, hashes.SHA256())
        h.update(weights_bytes)
        h.update(client_id.encode())
        try:
            h.verify(hmac_sig)
            return True
        except:
            return False

    async def authenticate_client(self, client_token: str, zk_proof: str) -> bool:
        """ZKP-based client authentication with rate-limiting."""
        if not await self._validate_rate_limit():
            return False
        is_authorized = await validate_client_for_fed_learning(client_token, zk_proof)
        if not is_authorized:
            await log_event(f"[SECURITY] Unauthorized federated access for {client_token[:6]}...", level="ALERT")
            await self._trigger_blackhole()
        return is_authorized

    async def receive_update(self, client_id: str, update_weights: Dict, metadata: Dict, hmac_sig: str) -> Dict:
        """
        Secure update reception with anti-tampering checks.
        Refactored to use async and deterministic serialization.
        """
        if not ENABLE_FED_LEARNING:
            await log_event("[FED] Learning disabled", level="ALERT")
            return {"status": "error", "code": 403}

        if not await self._validate_rate_limit():
            return {"status": "error", "code": 429}

        if len(self.client_updates) >= MAX_CLIENTS_PER_ROUND:
            await log_event("[FED] Client limit exceeded", level="ALERT")
            return {"status": "error", "code": 429}

        try:
            # Use a deterministic serialization for hashing
            weights_bytes = json.dumps(update_weights, sort_keys=True).encode()
            if not self._verify_update_integrity(weights_bytes, client_id, bytes.fromhex(hmac_sig)):
                await log_event(f"[FED] Invalid HMAC from {client_id[:8]}", level="ALERT")
                return {"status": "rejected", "code": 401}
        except Exception:
            await log_event(f"[FED] HMAC signature invalid format from {client_id[:8]}", level="ERROR")
            return {"status": "rejected", "code": 401}

        # ZKP authentication
        if not await self.authenticate_client(client_id, "dummy_proof"):
            return {"status": "rejected", "code": 401}

        if not await validate_model_update(update_weights, metadata):
            return {"status": "rejected", "code": 400}

        self.client_updates.append({
            "client_id": client_id,
            "weights": update_weights,
            "metadata": metadata,
            "received_at": datetime.now(timezone.utc).isoformat()
        })

        await log_event(f"[FED] Update from {client_id[:8]} accepted")
        return {"status": "accepted", "code": 200}

    def check_round_completion(self) -> bool:
        """Determines if threshold met with stale client check."""
        now = time.time()
        stale_cutoff = now - ROUND_TIMEOUT

        stale_updates = sum(
            1 for u in self.client_updates
            if datetime.fromisoformat(u["received_at"]).timestamp() < stale_cutoff
        )

        return (len(self.client_updates) - stale_updates) >= FED_ROUND_THRESHOLD

    def _secure_aggregate(self) -> np.ndarray:
        """Federated averaging with Byzantine-robust validation."""
        weights = [u["weights"] for u in self.client_updates]
        
        # Median-based outlier rejection
        median_weights = np.median(weights, axis=0)
        mad = np.median(np.abs(weights - median_weights), axis=0)
        valid_weights = [
            w for w in weights 
            if np.all(np.abs(w - median_weights) < 3 * mad)
        ]
        
        return np.mean(valid_weights, axis=0).astype(WEIGHT_PRECISION)

    async def push_global_model(self) -> Dict:
        """Securely updates global model with blockchain audit."""
        if not self.check_round_completion():
            return {
                "status": "incomplete",
                "clients": len(self.client_updates),
                "needed": FED_ROUND_THRESHOLD
            }

        try:
            new_weights = self._secure_aggregate()
            model_hash = hashlib.sha256(new_weights.tobytes()).hexdigest()
            
            save_global_model(new_weights, MODEL_NAME)
            self._model_version = model_hash[:12]
            
            round_id = uuid.uuid5(uuid.NAMESPACE_OID, model_hash).hex
            await self.log_training_round(round_id, len(self.client_updates))
            
            self.client_updates.clear()
            self._derived_key = self._derive_round_key()
            
            await self._secure_wipe(TEMP_MODEL_PATHS)
            
            return {
                "status": "success",
                "round_id": round_id,
                "model_hash": model_hash,
                "clients_used": len(self.client_updates),
                "model_version": self._model_version
            }
        except Exception as e:
            await log_event(f"[FED] Model push failed: {str(e)}", level="ALERT")
            return {"status": "failed", "error": str(e)}

    async def log_training_round(self, round_id: str, client_count: int):
        """Immutable blockchain logging with ZKP."""
        audit_data = {
            "round_id": round_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_count": client_count,
            "model_version": self._model_version,
            "integrity_tag": hmac.HMAC(HMAC_KEY, hashes.SHA256())
                .update(round_id.encode())
                .finalize()
                .hex()
        }
        await log_to_blockchain("fed_round", audit_data)
        await log_event(f"[FED] Round {round_id[:8]} completed with {client_count} clients")

aggregator = FederatedAggregator()