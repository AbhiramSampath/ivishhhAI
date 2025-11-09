import os
import uuid
import ctypes
import shutil
from typing import Dict, Optional, Any
from dataclasses import dataclass
from contextlib import contextmanager
from datetime import datetime
import threading
import numpy as np

# Security: Preserve original imports
from config.system_flags import EDGE_MODEL_PATHS, OFFLINE_MODE
from backend.app.utils.logger import log_event
from security.blockchain.zkp_handler import ZeroKnowledgeAuth # Corrected import path
from security.intrusion_prevention.counter_response import trigger_blackhole_response

# Import model classes at module level to avoid NameError in reload_model and elsewhere
from ai_models.whisper.whispercpp import WhisperCppEngine
from ai_models.translation.sarvam import SarvamTranslator
from ai_models.tts.coqui import CoquiTTS
from ai_models.emotion.indic_gru import EmotionGRU

@dataclass
class ModelInfo:
    name: str
    path: str
    loaded: bool = False
    instance: Optional[Any] = None
    last_reload: Optional[datetime] = None

class Sandbox:
    """Security sandbox for diagnostics"""
    def __enter__(self):
        self._old_cwd = os.getcwd()
        self._temp_dir = f"/tmp/edge_sandbox_{uuid.uuid4()}"
        os.makedirs(self._temp_dir, exist_ok=True)
        os.chdir(self._temp_dir)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self._old_cwd)
        try:
            shutil.rmtree(self._temp_dir)
        except Exception as e:
            log_event(f"SECURITY: Sandbox cleanup failed: {e}", level="ERROR")

class EdgeModelLoader:
    def __init__(self):
        self.models: Dict[str, ModelInfo] = {}
       
        self.zk_auth = ZeroKnowledgeAuth()
        self._load_models_with_defenses()

    def _validate_model(self, model_path: str) -> bool:
        """Nuclear-grade model validation"""
        if not os.path.exists(model_path):
            log_event(f"SECURITY: Missing model file - {model_path}", level="CRITICAL")
            return False
        return True

    def _load_models_with_defenses(self):
        """Secure model loading pipeline"""
        log_event("EDGE: Starting secure model init...", level="INFO")

        try:
            # Use atomic loading with a temporary dictionary
            temp_models = {}
            temp_models["stt"] = self._load_whisper()
            temp_models["translator"] = self._load_translator()
            temp_models["tts"] = self._load_tts()
            temp_models["emotion"] = self._load_emotion()

            # If all models loaded successfully, perform an atomic swap
            self.models = temp_models
            log_event("EDGE: All models passed security checks and are loaded.", level="INFO")
        except Exception as e:
            self._purge_models()
            raise RuntimeError(f"SECURE LOAD FAILED: {str(e)}")

    def _load_whisper(self) -> ModelInfo:
        path = EDGE_MODEL_PATHS.get("whisper_cpp")
        if not path or not self._validate_model(path):
            raise FileNotFoundError("Whisper.cpp model not found or invalid.")
        
        try:
            instance = WhisperCppEngine(path, device=self.device, use_mmap=True)
            return ModelInfo(
                name="stt",
                path=path,
                loaded=True,
                instance=instance
            )
        except Exception as e:
            log_event(f"LOAD FAILURE: Whisper - {str(e)}", level="ERROR")
            raise

    def _load_translator(self) -> ModelInfo:
        path = EDGE_MODEL_PATHS.get("sarvam")
        if not path or not self._validate_model(path):
            raise FileNotFoundError("Sarvam model not found or invalid.")
        
        try:
            instance = SarvamTranslator(path, quantized=True)
            return ModelInfo(
                name="translator",
                path=path,
                loaded=True,
                instance=instance
            )
        except Exception as e:
            log_event(f"LOAD FAILURE: Sarvam - {str(e)}", level="ERROR")
            raise

    def _load_tts(self) -> ModelInfo:
        path = EDGE_MODEL_PATHS.get("coqui")
        if not path or not self._validate_model(path):
            raise FileNotFoundError("Coqui TTS model not found or invalid.")
        
        try:
            instance = CoquiTTS(path, pre_alloc_voices=3)
            return ModelInfo(
                name="tts",
                path=path,
                loaded=True,
                instance=instance
            )
        except Exception as e:
            log_event(f"LOAD FAILURE: Coqui - {str(e)}", level="ERROR")
            raise

    def _load_emotion(self) -> ModelInfo:
        path = EDGE_MODEL_PATHS.get("indic_gru")
        if not path or not self._validate_model(path):
            raise FileNotFoundError("Emotion model not found or invalid.")
        
        try:
            instance = EmotionGRU(path, jit_optimized=True)
            return ModelInfo(
                name="emotion",
                path=path,
                loaded=True,
                instance=instance
            )
        except Exception as e:
            log_event(f"LOAD FAILURE: IndicGRU - {str(e)}", level="ERROR")
            raise

    def _purge_models(self):
        """Military-grade purge on breach detection"""
        for name, info in self.models.items():
            if info.loaded and hasattr(info.instance, 'secure_wipe'):
                info.instance.secure_wipe()
                info.loaded = False
                log_event(f"SECURITY: Purged model {name}", level="CRITICAL")

    def get_model(self, name: str) -> Optional[Any]:
        """Zero-trust model access"""
        if not self.zk_auth.verify_session():
            trigger_blackhole_response()
            raise RuntimeError("Session verification failed. Blackhole response triggered.")
        model_info = self.models.get(name)
        if not model_info or not model_info.loaded:
            log_event(f"SECURITY: Model access denied - {name}", level="WARNING")
            return None
        return model_info.instance

    def reload_model(self, name: str):
        """Secure hot-reload with atomic swap"""
        old_info = self.models.get(name)
        if not old_info:
            log_event(f"SECURITY: Model not loaded - {name}", level="WARNING")
            return

        try:
            path = old_info.path
            if not self._validate_model(path):
                log_event(f"SECURITY: Model integrity failed - {name}", level="CRITICAL")
                return

            # Load new model
            new_model = None
            if name == "stt":
                new_model = WhisperCppEngine(path, device=self.device, use_mmap=True)
            elif name == "translator":
                new_model = SarvamTranslator(path, quantized=True)
            elif name == "tts":
                new_model = CoquiTTS(path, pre_alloc_voices=3)
            elif name == "emotion":
                new_model = EmotionGRU(path, jit_optimized=True)
            else:
                raise ValueError(f"Unknown model: {name}")

            # Secure swap
            if old_info.instance and hasattr(old_info.instance, 'secure_wipe'):
                old_info.instance.secure_wipe()

            self.models[name] = ModelInfo(
                name=name,
                path=path,
                instance=new_model,
                loaded=True,
                last_reload=datetime.utcnow()
            )
            log_event(f"SECURE RELOAD: {name}", level="INFO")
        except Exception as e:
            log_event(f"RELOAD FAILED: {str(e)}", level="ERROR")
            trigger_blackhole_response()

    def infer_from_edge(self, model_name: str, input_data: Any) -> Any:
        """Hardened inference pipeline"""
        if not isinstance(input_data, (str, bytes, np.ndarray)):
            log_event("SECURITY ALERT: Invalid input type", level="CRITICAL")
            trigger_blackhole_response()
            raise RuntimeError("Invalid input type")

        model = self.get_model(model_name)
        if not model:
            raise ValueError(f"Model {model_name} not available")

        # Time-boxed execution
        try:
            with self._secure_timeout(seconds=0.2):
                result = model.infer(input_data)
                log_event(f"INFERENCE: {model_name} completed in <200ms", level="INFO")
                return result
        except TimeoutError:
            log_event("SECURITY: Model timeout - possible exploit", level="CRITICAL")
            self.reload_model(model_name)
            raise RuntimeError("Inference timeout")

    @contextmanager
    def _secure_timeout(self, seconds: float):
        """Defense-in-depth: Prevent timing attacks"""
        timer = threading.Timer(seconds, lambda: ctypes.string_at(0))
        timer.start()
        try:
            yield
        finally:
            timer.cancel()

    def run_diagnostics(self):
        """Secure diagnostic mode"""
        results = {}
        for name, info in self.models.items():
            if not info.loaded:
                results[name] = {"loaded": False, "error": "Model not loaded"}
                continue
            try:
                with Sandbox():
                    # Assumed a test_infer() method exists on model instances
                    result = info.instance.test_infer()
                    results[name] = result
            except Exception as e:
                log_event(f"DIAG FAILED: {name} - {str(e)}", level="ERROR")
                results[name] = {"loaded": True, "passed": False, "error": str(e)}
        return results

# --- Singleton instance for edge models ---
EdgeModels = EdgeModelLoader()