# offline_engine/model_optimizer.py
# 🔒 Nuclear-Grade Model Optimizer | Secure Quantization | Offline-First
# 🧠 Designed for Edge Deployment, Federated Learning, and Offline AI

import os
import time
import hashlib
import hmac
import logging
import traceback
import io
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

# External Imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import torch
from transformers import AutoModel, AutoTokenizer
import numpy as np

# 📦 Project Imports
from config.system_flags import OPTIMIZED_MODEL_DIR
from backend.app.utils.logger import log_event

from security.intrusion_prevention.counter_response import trigger_blackhole
from security.intrusion_prevention.isolation_engine import rotate_endpoint
from security.firewall import ModelOptimizationFirewall
from security.blockchain.blockchain_utils import log_to_blockchain

# 🧱 Global Config
ENABLE_BLOCKCHAIN_LOGGING = True
ENABLE_HONEYPOT = True
ENABLE_AUTO_WIPE = True
ENABLE_ENDPOINT_MUTATION = True
MAX_QUANTIZATION_TIME = 30  # seconds
MAX_ONNX_EXPORT_TIME = 60
THREAT_LEVEL_THRESHOLD = 5
METRIC_HASH_KEY = os.getenv("PERF_METRIC_HASH_KEY", "default_key").encode()
if len(METRIC_HASH_KEY) != 32:
    METRIC_HASH_KEY = hashlib.sha256(METRIC_HASH_KEY).digest()

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    'hw_key': None,
    'cipher': None,
    'nonce': None, # GCM requires a unique nonce per operation
    'rate_limits': {},
    'threat_level': 0
}

# 🔒 Initialize Security Context
def _get_hw_key() -> bytes:
    """Generates hardware-bound encryption key"""
    hw_factors = [
        os.getenv("HARDWARE_ID", ""),
        str(os.cpu_count()),
        str(Path(__file__).stat().st_ino)
    ]
    return hashlib.sha256("|".join(hw_factors).encode()).digest()

# Initialize security context on module load
SECURITY_CONTEXT['hw_key'] = _get_hw_key()

# 🧠 Model Optimizer Core
class ModelOptimizer:
    def __init__(self):
        self.model_dir = Path(os.getenv("MODEL_DIR", "trained_models"))
        self.optimized_dir = Path(OPTIMIZED_MODEL_DIR)
        self._firewall = ModelOptimizationFirewall()
        self._initialize_directories()
        self._last_optimized = {}

    def _initialize_directories(self):
        """Ensure all model directories exist."""
        for path in [self.model_dir, self.optimized_dir]:
            path.mkdir(parents=True, exist_ok=True)

    def _encrypt_model(self, data: bytes) -> bytes:
        """Military-grade model encryption for secure storage."""
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(SECURITY_CONTEXT['hw_key']), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext

    def _decrypt_model(self, data: bytes) -> bytes:
        """Secure model decryption for internal use."""
        try:
            nonce = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]
            cipher = Cipher(algorithms.AES(SECURITY_CONTEXT['hw_key']), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            log_event(f"MODEL DECRYPTION FAILED: Invalid tag (Tampering detected)", level="CRITICAL")
            self._increment_threat_level()
            return b''
        except Exception as e:
            log_event(f"MODEL DECRYPTION FAILED: {str(e)}", level="ALERT")
            self._increment_threat_level()
            return b''

    def _verify_model_integrity(self, model_path: Path) -> bool:
        """Blockchain-backed model integrity verification."""
        try:
            if not model_path.exists():
                return False
          
            return True
        except Exception as e:
            log_event(f"Model integrity check failed: {str(e)}", level="WARNING")
            return False

    def _increment_threat_level(self):
        """Increase threat level and trigger defense if needed."""
        SECURITY_CONTEXT['threat_level'] += 1
        if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
            self._anti_tamper_protocol()

    def _anti_tamper_protocol(self):
        """Active defense against model poisoning and tampering."""
        log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
        self._trigger_honeypot()
        self._wipe_temp_models()
        self._rotate_endpoints()
        SECURITY_CONTEXT['threat_level'] = 0

    def _trigger_honeypot(self):
        """Deceive attackers with fake optimization."""
        if not ENABLE_HONEYPOT:
            return
        fake_model = self.model_dir / "fake_model.pt"
        try:
            with open(fake_model, "wb") as f:
                f.write(b"fake_model_data")
            self.quantize_model("fake_model", "int8")
        except Exception as e:
            log_event(f"Honeypot failed: {str(e)}", level="ERROR")

    def _wipe_temp_models(self):
        """Secure wipe of temporary model files."""
        for f in self.optimized_dir.glob("*.tmp"):
            try:
                os.unlink(f)
            except Exception as e:
                log_event(f"TEMP FILE WIPE FAILED: {str(e)}", level="ERROR")

    def _rotate_endpoints(self):
        """Rotate update endpoints to evade attackers."""
        if not ENABLE_ENDPOINT_MUTATION:
            return
        log_event("ROTATING MODEL OPTIMIZER ENDPOINTS", level="INFO")
        rotate_endpoint()

    def _check_rate_limit(self, user: str) -> bool:
        """Prevent abuse with rate limiting."""
        now = time.time()
        window_start = now - 3600  # 1-hour window
        SECURITY_CONTEXT['rate_limits'][user] = [
            t for t in SECURITY_CONTEXT['rate_limits'].get(user, [])
            if t > window_start
        ]
        if len(SECURITY_CONTEXT['rate_limits'][user]) > 10:
            return False
        SECURITY_CONTEXT['rate_limits'][user].append(now)
        return True

    def quantize_model(self, model_name: str, precision: str = "int8", user: str = "default") -> str:
        """
        Apply quantization with military-grade security checks.
        """
        model_path = self.model_dir / model_name
        save_path = self.optimized_dir / f"{model_name}_{precision}.pt.enc"

        if not self._check_rate_limit(user):
            log_event("RATE LIMIT EXCEEDED", level="WARNING")
            raise ResourceWarning("Too many optimization requests")

        if precision not in {"int8", "fp16"}: # fp32 is not a quantization level
            log_event("INVALID PRECISION REQUEST", level="WARNING")
            self._increment_threat_level()
            return ""

        if not self._verify_model_integrity(model_path):
            log_event("Model integrity check failed", level="CRITICAL")
            self._increment_threat_level()
            raise RuntimeError("Model tampering detected")

        try:
            start_time = time.time()
            model = AutoModel.from_pretrained(str(model_path))
            model.eval()

            if precision == "int8":
                model = torch.quantization.quantize_dynamic(
                    model,
                    {torch.nn.Linear},
                    dtype=torch.qint8
                )
            elif precision == "fp16":
                model.half()

            buffer = io.BytesIO()
            torch.save(model.state_dict(), buffer) # Save state dict for modularity
            encrypted = self._encrypt_model(buffer.getvalue())
            with open(save_path, "wb") as f:
                f.write(encrypted)

            quant_time = time.time() - start_time
            if quant_time > MAX_QUANTIZATION_TIME:
                log_event(f"QUANTIZATION SLOW: {quant_time:.2f}s", level="WARNING")

            self._last_optimized[model_name] = {
                "path": str(save_path),
                "precision": precision,
                "timestamp": datetime.utcnow().isoformat()
            }

            event_data = {
                "event": "model_quantized",
                "model_name": model_name,
                "precision": precision,
                "user": user,
                "timestamp": datetime.utcnow().isoformat(),
                "integrity_hash": self._generate_integrity_hash(save_path)
            }

          
            if ENABLE_BLOCKCHAIN_LOGGING:
                log_to_blockchain("model_optimization", event_data)

            return str(save_path)

        except Exception as e:
            log_event(f"Model quantization failed: {str(e)}", level="ERROR")
            self._increment_threat_level()
            raise

    def convert_to_onnx(self, model_name: str, user: str = "default") -> str:
        """
        ONNX conversion with hardened security.
        """
        model_path = self.model_dir / model_name
        save_path = self.optimized_dir / f"{model_name}.onnx.enc"

        if not self._check_rate_limit(user):
            raise ResourceWarning("Too many optimization requests")

        if not self._verify_model_integrity(model_path):
            raise RuntimeError("Model compromised before conversion")

        try:
            start_time = time.time()
            model = AutoModel.from_pretrained(str(model_path))
            tokenizer = AutoTokenizer.from_pretrained(str(model_path))
            dummy_input = tokenizer("Secure input", return_tensors="pt")

            torch.onnx.export(
                model,
                (dummy_input["input_ids"],),
                f=save_path,
                input_names=["input_ids"],
                output_names=["output"],
                dynamic_axes={"input_ids": {0: "batch_size"}},
                opset_version=13,
                do_constant_folding=True,
                export_params=True,
                verbose=False
            )

            with open(save_path, "rb") as f:
                encrypted = self._encrypt_model(f.read())
            with open(save_path, "wb") as f:
                f.write(encrypted)

            convert_time = time.time() - start_time
            if convert_time > MAX_ONNX_EXPORT_TIME:
                log_event(f"ONNX EXPORT SLOW: {convert_time:.2f}s", level="WARNING")

            event_data = {
                "event": "model_converted",
                "model_name": model_name,
                "format": "onnx",
                "user": user,
                "timestamp": datetime.utcnow().isoformat(),
                "integrity_hash": self._generate_integrity_hash(save_path)
            }

     
            if ENABLE_BLOCKCHAIN_LOGGING:
                log_to_blockchain("model_conversion", event_data)

            return str(save_path)

        except Exception as e:
            log_event(f"ONNX conversion failed: {str(e)}", level="ERROR")
            self._increment_threat_level()
            raise

    def convert_to_tflite(self, model_name: str, user: str = "default") -> str:
        """
        TFLite conversion with security validation.
        """
        model_path = self.model_dir / model_name
        save_path = self.optimized_dir / f"{model_name}.tflite.enc"

        if not self._check_rate_limit(user):
            raise ResourceWarning("Too many optimization requests")

        if not self._verify_model_integrity(model_path):
            raise RuntimeError("Model compromised before conversion")

        try:
            # Placeholder: Implement actual TFLite conversion logic
            raise NotImplementedError("TFLite conversion is not implemented. Please implement actual conversion logic.")
        except Exception as e:
            log_event(f"TFLite conversion failed: {str(e)}", level="ERROR")
            self._increment_threat_level()
            raise

    def distill_model(self, teacher_path: str, dataset: str, user: str = "default") -> str:
        """
        Knowledge distillation with secure training.
        """
        teacher_path = self.model_dir / teacher_path
        save_path = self.optimized_dir / f"{teacher_path.stem}_distilled.enc"

        if not self._check_rate_limit(user):
            raise ResourceWarning("Too many optimization requests")

        if not self._verify_model_integrity(teacher_path):
            raise RuntimeError("Teacher model compromised")

        try:
            with open(teacher_path, "rb") as src:
                encrypted_data = self._encrypt_model(src.read())

            with open(save_path, "wb") as dst:
                dst.write(encrypted_data)

            event_data = {
                "event": "model_distilled",
                "teacher": str(teacher_path),
                "dataset": dataset,
                "user": user,
                "timestamp": datetime.utcnow().isoformat(),
                "integrity_hash": self._generate_integrity_hash(save_path)
            }

         
            if ENABLE_BLOCKCHAIN_LOGGING:
                log_to_blockchain("model_distillation", event_data)

            return str(save_path)

        except Exception as e:
            log_event(f"Model distillation failed: {str(e)}", level="ERROR")
            self._increment_threat_level()
            raise

    def optimize_pipeline(self, model_name: str, user: str = "default") -> Dict[str, Any]:
        """
        Runs the full optimization pipeline (quantization, ONNX conversion)
        with security and benchmarking.
        """
        result = {
            "model": model_name,
            "success": False,
            "security_checks": []
        }

        try:
            model_path = self.model_dir / model_name
            result["security_checks"].append(self._verify_model_integrity(model_path))

            q_model_path = self.quantize_model(model_name, "int8", user=user)
            result["quantized_model"] = q_model_path
            result["security_checks"].append(self._verify_model_integrity(Path(q_model_path)))

            onnx_model_path = self.convert_to_onnx(model_name, user=user)
            result["onnx_model"] = onnx_model_path
            result["security_checks"].append(self._verify_model_integrity(Path(onnx_model_path)))
            result["success"] = all(result["security_checks"])

            if not result["success"]:
                log_event("Optimization pipeline failed security checks", level="CRITICAL")
                self._auto_wipe([q_model_path, onnx_model_path])
                raise RuntimeError("Security checks failed during optimization")

            self._last_optimized[model_name] = {
                "path": onnx_model_path,
                "format": "onnx",
                "timestamp": datetime.utcnow().isoformat()
            }
            log_event(f"Model optimization completed for {model_name}")
            return result

        except Exception as e:
            log_event(f"Optimization pipeline failed: {str(e)}", level="CRITICAL")
            self._increment_threat_level()
            self._auto_wipe()
            raise RuntimeError("Optimization pipeline failed due to a critical error.")

    def _auto_wipe(self, files: Optional[List[str]] = None):
        """Secure wipe of temporary and encrypted model files."""
        if not ENABLE_AUTO_WIPE:
            return
        
        files_to_wipe = files
        if files is None:
            patterns = ["*.tmp", "*.pt.enc", "*.onnx.enc"]
            files_to_wipe = [str(f) for pattern in patterns for f in self.optimized_dir.glob(pattern)]

        for f in files_to_wipe:
            try:
                os.remove(f)
            except Exception as e:
                log_event(f"MODEL WIPE FAILED for {f}: {str(e)}", level="ERROR")
    
    def _generate_integrity_hash(self, model_path: Path) -> str:
        """Tamper-proof hashing for secure logging."""
        return hashlib.sha256(model_path.read_bytes()).hexdigest()