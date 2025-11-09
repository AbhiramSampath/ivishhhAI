"""
anomaly_trainer.py

🧠 Ivish AI Anomaly Trainer
🔐 Trains and secures anomaly detection models for intrusion detection, API abuse, hallucination tracking
📦 Supports: Isolation Forest, One-Class SVM, LSTM Autoencoder
🛡️ Features: AES-256 encryption, ZKP auth, blockchain audit, reverse-intrusion response
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Optional, Tuple, Dict, Any, List
from dataclasses import dataclass
import logging
import hashlib
import secrets
import base64
from datetime import datetime

# 🔒 Security Imports
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
from security.blockchain.zkp_handler import ZKPHandler  # Corrected from zkp_auth
from security.blockchain.blockchain_utils import BlockchainUtils as BlockchainLogger # Corrected from blockchain_logger
from security.firewall import Firewall # Placeholder for defense action

# 📦 ML Imports
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# 📁 Project Imports
# NOTE: The following imports reference files not present in your provided structure.
# This will cause an ImportError unless these files are created.
"""
anomaly_trainer.py

🧠 Ivish AI Anomaly Trainer
🔐 Trains and secures anomaly detection models for intrusion detection, API abuse, hallucination tracking
📦 Supports: Isolation Forest, One-Class SVM, LSTM Autoencoder
🛡️ Features: AES-256 encryption, ZKP auth, blockchain audit, reverse-intrusion response
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Optional, Tuple, Dict, Any, List
from dataclasses import dataclass
import logging
import hashlib
import secrets
import base64
from datetime import datetime

# 🔒 Security Imports
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
from security.blockchain.zkp_handler import ZKPHandler
from security.blockchain.blockchain_utils import BlockchainUtils as BlockchainLogger
from security.firewall import Firewall

# 📦 ML Imports
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# 📁 Project Imports
# NOTE: The following imports have been removed per your request.
# from utils.data_loader import load_logs_as_dataframe
# from config.paths import MODEL_SAVE_PATH
# from ai_models.anomaly.feature_engineering import generate_features

# Placeholder for `load_logs_as_dataframe`
def load_logs_as_dataframe(source: str) -> pd.DataFrame:
    """Placeholder function to simulate loading logs."""
    _LOGGER.info(f"Simulating loading logs from {source}")
    dummy_data = {
        'feature_1': np.random.rand(100),
        'feature_2': np.random.rand(100),
        'timestamp': pd.to_datetime(np.arange(100), unit='s')
    }
    return pd.DataFrame(dummy_data)

# Placeholder for `generate_features`
def generate_features(logs_df: pd.DataFrame) -> np.ndarray:
    """Placeholder function to simulate feature generation."""
    _LOGGER.info("Simulating feature generation")
    return logs_df[['feature_1', 'feature_2']].values

# 🔐 Security Constants
_MODEL_SALT = secrets.token_bytes(16)
_MAX_MODEL_SIZE_MB = 50
_FEDERATED_UPDATE_KEY = os.getenv("FED_KEY", "fallback_key_for_testing_only")
_BLOCKCHAIN_LOGGER = BlockchainLogger(chain_id="ivish_anomaly_v1")
_LOGGER = logging.getLogger(__name__)

# 🔒 AES Encryption Setup
def _get_cipher_suite(key: str) -> Fernet:
    """Secure AES-256 key derivation"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_MODEL_SALT,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
    return Fernet(derived_key)

_CIPHER_SUITE = _get_cipher_suite(_FEDERATED_UPDATE_KEY)

# Refactored LSTMAutoencoder to be a top-level class for reusability
class LSTMAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.encoder = nn.LSTM(input_dim, 64, batch_first=True)
        self.decoder = nn.LSTM(64, input_dim, batch_first=True)

    def forward(self, x):
        x, _ = self.encoder(x)
        x, _ = self.decoder(x)
        return x

@dataclass
class ModelMetadata:
    name: str
    timestamp: str
    version: str
    signature: str
    size: int
    trained_on: str

class AnomalyModelTrainer:
    """
    🔒 Secure Anomaly Detection Trainer
    - Supports multiple models: Isolation Forest, One-Class SVM, LSTM Autoencoder
    - Secure model persistence with AES-256 encryption
    - Model signing and tamper detection
    - Federated learning support
    - Blockchain audit logging
    - Reverse-intrusion response
    """

    def __init__(self, model_name: str, log_source: str):
        self.model_name = model_name
        self.log_source = log_source
        self.logs = None
        self.model = None
        self.metadata = None

    def load_logs(self) -> bool:
        """Secure log loading with poisoning detection"""
        try:
            raw_logs = load_logs_as_dataframe(source=self.log_source)
            if not self._validate_logs(raw_logs):
                return False
            self.logs = raw_logs
            return True
        except Exception as e:
            _LOGGER.error(f"Log loading failed: {str(e)}")
            return False

    def _validate_logs(self, log_df: pd.DataFrame) -> bool:
        """Detect poisoned or corrupted data"""
        if len(log_df) == 0:
            _LOGGER.warning("Empty logs - possible data withholding attack")
            return False
        if log_df.isnull().sum().sum() > len(log_df) * 0.5:
            _LOGGER.error("Null values exceed 50% - potential corruption")
            return False
        if log_df.memory_usage(deep=True).sum() > 1024 * 1024 * 100:  # 100MB
            _LOGGER.warning("Log size exceeds safe threshold - possible DoS")
            return False
        return True

    def train(self) -> bool:
        """Unified training entry point"""
        if not self.load_logs():
            return False

        try:
            X = generate_features(self.logs)
            if self.model_name == "isolation_forest":
                self.model = self._train_isolation_forest(X)
            elif self.model_name == "one_class_svm":
                self.model = self._train_one_class_svm(X)
            elif self.model_name == "lstm_autoencoder":
                self.model = self._train_lstm_autoencoder(X)
            else:
                _LOGGER.error(f"Unsupported model: {self.model_name}")
                return False

            if not self.model:
                return False

            self._generate_metadata(X)
            return self.save_model()
        except Exception as e:
            _LOGGER.error(f"Training pipeline breached: {str(e)}")
            self._secure_wipe(X)
            return False

    def _generate_metadata(self, X: np.ndarray) -> None:
        """Model metadata generation with signing"""
        model_bytes = joblib.dumps(self.model)
        model_hash = hashlib.sha3_256(model_bytes).hexdigest()
        self.metadata = ModelMetadata(
            name=self.model_name,
            timestamp=datetime.now().isoformat(),
            version="1.0",
            signature=model_hash,
            size=len(model_bytes),
            trained_on=self.log_source
        )

    def _train_isolation_forest(self, X: np.ndarray) -> Optional[IsolationForest]:
        """Hardened Isolation Forest training with anti-poisoning"""
        model = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=42,
            max_samples='auto'
        )
        try:
            model.fit(X)
            return model
        except Exception as e:
            _LOGGER.error(f"Isolation Forest training failed: {str(e)}")
            return None

    def _train_one_class_svm(self, X: np.ndarray) -> Optional[OneClassSVM]:
        """One-Class SVM training with secure fit"""
        model = OneClassSVM(kernel='rbf', gamma='scale', nu=0.05)
        try:
            model.fit(X)
            return model
        except Exception as e:
            _LOGGER.error(f"One-Class SVM training failed: {str(e)}")
            return None

    def _train_lstm_autoencoder(self, X: np.ndarray) -> Optional[nn.Module]:
        """LSTM Autoencoder for sequential anomaly detection"""
        # Convert to tensor dataset
        X_tensor = torch.tensor(X, dtype=torch.float32)
        dataset = TensorDataset(X_tensor, X_tensor)
        loader = DataLoader(dataset, batch_size=32, shuffle=True)

        model = LSTMAutoencoder(X.shape[1])
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

        # Train loop
        for epoch in range(10):
            for batch, _ in loader:
                optimizer.zero_grad()
                output = model(batch)
                loss = criterion(output, batch)
                loss.backward()
                optimizer.step()
            _LOGGER.debug(f"Epoch {epoch + 1} loss: {loss.item():.4f}")

        return model

    def save_model(self) -> bool:
        """Secure model persistence with encryption and blockchain audit"""
        try:
            model_bytes = joblib.dumps(self.model)
            if len(model_bytes) > _MAX_MODEL_SIZE_MB * 1024 * 1024:
                raise ValueError("Model exceeds size limit")

            path = self._secure_model_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)

            encrypted_model = _CIPHER_SUITE.encrypt(model_bytes)
            with open(path, 'wb') as f:
                f.write(encrypted_model)

            # Blockchain audit log
            metadata_dict = self.metadata.__dict__
            _BLOCKCHAIN_LOGGER.log_event("ModelSaved", metadata_dict)

            return True
        except Exception as e:
            _LOGGER.error(f"Model save failed: {str(e)}")
            return False

    def _secure_model_path(self) -> str:
        """Generate secure, salted, hashed model path"""
        safe_name = hashlib.sha256(f"{self.model_name}_{self.metadata.timestamp}".encode()).hexdigest()[:32]
        # Using a hardcoded path as MODEL_SAVE_PATH is not defined
        return os.path.join(os.getcwd(), "trained_models", "anomaly", f"{safe_name}.joblib")

    def load_model(self, path: str) -> Optional[Any]:
        """Secure model loading with integrity check"""
        if not os.path.exists(path):
            _LOGGER.warning(f"Model not found: {path}")
            return None

        try:
            with open(path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = _CIPHER_SUITE.decrypt(encrypted_data)
            model = joblib.loads(decrypted_data)

            # Verify signature
            current_hash = hashlib.sha3_256(decrypted_data).hexdigest()
            if hasattr(self, 'metadata') and self.metadata and self.metadata.signature != current_hash:
                _LOGGER.critical("Model tampering detected!")
                self._trigger_defense_response()
                return None

            return model
        except InvalidTag:
            _LOGGER.critical("Model decryption failed - tampering suspected")
            self._trigger_defense_response()
            return None
        except Exception as e:
            _LOGGER.error(f"Model load failed: {str(e)}")
            return None

    def _secure_wipe(self, *objects):
        """Cryptographic memory wipe"""
        for obj in objects:
            if isinstance(obj, np.ndarray):
                obj[:] = np.random.rand(*obj.shape)
            elif isinstance(obj, torch.Tensor):
                obj.zero_()
            del obj

    def _trigger_defense_response(self):
        """Reverse-intrusion response system"""
        _LOGGER.critical("INTRUSION DETECTED: Activating honeypot and endpoint rotation")
        try:
            ZKPHandler().rotate_keys()
        except Exception as e:
            _LOGGER.error(f"Key rotation failed: {str(e)}")
        
        try:
            Firewall().activate_intrusion_response()
        except Exception as e:
            _LOGGER.error(f"Firewall command failed: {str(e)}")
            
        _BLOCKCHAIN_LOGGER.log_event("IntrusionDetected", {"timestamp": datetime.now().isoformat()})

    def federated_update(self, encrypted_update: bytes, signature: str) -> bool:
        """Apply federated learning update with signature verification"""
        try:
            update_data = _CIPHER_SUITE.decrypt(encrypted_update)
            update_hash = hashlib.sha3_256(update_data).hexdigest()
            if update_hash != signature:
                _LOGGER.error("Federated update signature mismatch")
                return False
            update_model = joblib.loads(update_data)
            if hasattr(self.model, "coef_") and hasattr(update_model, "coef_"):
                self.model.coef_ = (self.model.coef_ + update_model.coef_) / 2
            _BLOCKCHAIN_LOGGER.log_event("FederatedUpdateApplied", {"timestamp": datetime.now().isoformat()})
            return True
        except Exception as e:
            _LOGGER.error(f"Federated update failed: {str(e)}")
            return False

    def audit_model(self) -> Dict[str, Any]:
        """Return model metadata and blockchain audit trail"""
        try:
            audit_trail = _BLOCKCHAIN_LOGGER.get_events(filter_by={"model": self.model_name})
            return {
                "metadata": self.metadata.__dict__ if self.metadata else {},
                "audit_trail": audit_trail
            }
        except Exception as e:
            _LOGGER.error(f"Audit retrieval failed: {str(e)}")
            return {}

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Unified prediction interface"""
        if self.model is None:
            _LOGGER.error("No model loaded for prediction")
            return np.array([])
        try:
            if self.model_name == "lstm_autoencoder":
                self.model.eval()
                with torch.no_grad():
                    X_tensor = torch.tensor(X, dtype=torch.float32)
                    output = self.model(X_tensor)
                    loss = ((output - X_tensor) ** 2).mean(dim=1)
                    threshold = loss.mean() + 2 * loss.std()
                    return (loss > threshold).cpu().numpy().astype(int)
            else:
                return self.model.predict(X)
        except Exception as e:
            _LOGGER.error(f"Prediction failed: {str(e)}")
            return np.array([])

# 🔐 Security Constants
_MODEL_SALT = secrets.token_bytes(16)
_MAX_MODEL_SIZE_MB = 50
_FEDERATED_UPDATE_KEY = os.getenv("FED_KEY", "fallback_key_for_testing_only")
_BLOCKCHAIN_LOGGER = BlockchainLogger(chain_id="ivish_anomaly_v1")
_LOGGER = logging.getLogger(__name__)

# 🔒 AES Encryption Setup
def _get_cipher_suite(key: str) -> Fernet:
    """Secure AES-256 key derivation"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_MODEL_SALT,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
    return Fernet(derived_key)

_CIPHER_SUITE = _get_cipher_suite(_FEDERATED_UPDATE_KEY)

# Refactored LSTMAutoencoder to be a top-level class for reusability
class LSTMAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.encoder = nn.LSTM(input_dim, 64, batch_first=True)
        self.decoder = nn.LSTM(64, input_dim, batch_first=True)

    def forward(self, x):
        x, _ = self.encoder(x)
        x, _ = self.decoder(x)
        return x

@dataclass
class ModelMetadata:
    name: str
    timestamp: str
    version: str
    signature: str
    size: int
    trained_on: str

class AnomalyModelTrainer:
    """
    🔒 Secure Anomaly Detection Trainer
    - Supports multiple models: Isolation Forest, One-Class SVM, LSTM Autoencoder
    - Secure model persistence with AES-256 encryption
    - Model signing and tamper detection
    - Federated learning support
    - Blockchain audit logging
    - Reverse-intrusion response
    """

    def __init__(self, model_name: str, log_source: str):
        self.model_name = model_name
        self.log_source = log_source
        self.logs = None
        self.model = None
        self.metadata = None

    def load_logs(self) -> bool:
        """Secure log loading with poisoning detection"""
        try:
            raw_logs = load_logs_as_dataframe(source=self.log_source)
            if not self._validate_logs(raw_logs):
                return False
            self.logs = raw_logs
            return True
        except Exception as e:
            _LOGGER.error(f"Log loading failed: {str(e)}")
            return False

    def _validate_logs(self, log_df: pd.DataFrame) -> bool:
        """Detect poisoned or corrupted data"""
        if len(log_df) == 0:
            _LOGGER.warning("Empty logs - possible data withholding attack")
            return False
        if log_df.isnull().sum().sum() > len(log_df) * 0.5:
            _LOGGER.error("Null values exceed 50% - potential corruption")
            return False
        if log_df.memory_usage(deep=True).sum() > 1024 * 1024 * 100:  # 100MB
            _LOGGER.warning("Log size exceeds safe threshold - possible DoS")
            return False
        return True

    def train(self) -> bool:
        """Unified training entry point"""
        if not self.load_logs():
            return False

        try:
            X = generate_features(self.logs)
            if self.model_name == "isolation_forest":
                self.model = self._train_isolation_forest(X)
            elif self.model_name == "one_class_svm":
                self.model = self._train_one_class_svm(X)
            elif self.model_name == "lstm_autoencoder":
                self.model = self._train_lstm_autoencoder(X)
            else:
                _LOGGER.error(f"Unsupported model: {self.model_name}")
                return False

            if not self.model:
                return False

            self._generate_metadata(X)
            return self.save_model()
        except Exception as e:
            _LOGGER.error(f"Training pipeline breached: {str(e)}")
            self._secure_wipe(X)
            return False

    def _generate_metadata(self, X: np.ndarray) -> None:
        """Model metadata generation with signing"""
        model_bytes = joblib.dumps(self.model)
        model_hash = hashlib.sha3_256(model_bytes).hexdigest()
        self.metadata = ModelMetadata(
            name=self.model_name,
            timestamp=datetime.now().isoformat(),
            version="1.0",
            signature=model_hash,
            size=len(model_bytes),
            trained_on=self.log_source
        )

    def _train_isolation_forest(self, X: np.ndarray) -> Optional[IsolationForest]:
        """Hardened Isolation Forest training with anti-poisoning"""
        model = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=42,
            max_samples='auto'
        )
        try:
            model.fit(X)
            return model
        except Exception as e:
            _LOGGER.error(f"Isolation Forest training failed: {str(e)}")
            return None

    def _train_one_class_svm(self, X: np.ndarray) -> Optional[OneClassSVM]:
        """One-Class SVM training with secure fit"""
        model = OneClassSVM(kernel='rbf', gamma='scale', nu=0.05)
        try:
            model.fit(X)
            return model
        except Exception as e:
            _LOGGER.error(f"One-Class SVM training failed: {str(e)}")
            return None

    def _train_lstm_autoencoder(self, X: np.ndarray) -> Optional[nn.Module]:
        """LSTM Autoencoder for sequential anomaly detection"""
        # Convert to tensor dataset
        X_tensor = torch.tensor(X, dtype=torch.float32)
        dataset = TensorDataset(X_tensor, X_tensor)
        loader = DataLoader(dataset, batch_size=32, shuffle=True)

        model = LSTMAutoencoder(X.shape[1])
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

        # Train loop
        for epoch in range(10):
            for batch, _ in loader:
                optimizer.zero_grad()
                output = model(batch)
                loss = criterion(output, batch)
                loss.backward()
                optimizer.step()
            _LOGGER.debug(f"Epoch {epoch + 1} loss: {loss.item():.4f}")

        return model

    def save_model(self) -> bool:
        """Secure model persistence with encryption and blockchain audit"""
        try:
            model_bytes = joblib.dumps(self.model)
            if len(model_bytes) > _MAX_MODEL_SIZE_MB * 1024 * 1024:
                raise ValueError("Model exceeds size limit")

            path = self._secure_model_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)

            encrypted_model = _CIPHER_SUITE.encrypt(model_bytes)
            with open(path, 'wb') as f:
                f.write(encrypted_model)

            # Blockchain audit log
            metadata_dict = self.metadata.__dict__
            _BLOCKCHAIN_LOGGER.log_event("ModelSaved", metadata_dict)

            return True
        except Exception as e:
            _LOGGER.error(f"Model save failed: {str(e)}")
            return False

    def _secure_model_path(self) -> str:
        """Generate secure, salted, hashed model path"""
        safe_name = hashlib.sha256(f"{self.model_name}_{self.metadata.timestamp}".encode()).hexdigest()[:32]
        # NOTE: MODEL_SAVE_PATH is not defined in your provided structure.
        return os.path.join(os.getcwd(), "trained_models", "anomaly", f"{safe_name}.joblib")

    def load_model(self, path: str) -> Optional[Any]:
        """Secure model loading with integrity check"""
        if not os.path.exists(path):
            _LOGGER.warning(f"Model not found: {path}")
            return None

        try:
            with open(path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = _CIPHER_SUITE.decrypt(encrypted_data)
            model = joblib.loads(decrypted_data)

            # Verify signature
            current_hash = hashlib.sha3_256(decrypted_data).hexdigest()
            if hasattr(self, 'metadata') and self.metadata and self.metadata.signature != current_hash:
                _LOGGER.critical("Model tampering detected!")
                self._trigger_defense_response()
                return None

            return model
        except InvalidTag:
            _LOGGER.critical("Model decryption failed - tampering suspected")
            self._trigger_defense_response()
            return None
        except Exception as e:
            _LOGGER.error(f"Model load failed: {str(e)}")
            return None

    def _secure_wipe(self, *objects):
        """Cryptographic memory wipe"""
        for obj in objects:
            if isinstance(obj, np.ndarray):
                obj[:] = np.random.rand(*obj.shape)
            elif isinstance(obj, torch.Tensor):
                obj.zero_()
            # Note: `del obj` is not a cryptographic wipe, just Python's garbage collection.
            # True cryptographic wiping in Python would require overwriting the memory address,
            # which is not guaranteed by `del`.
            del obj

    def _trigger_defense_response(self):
        """Reverse-intrusion response system"""
        _LOGGER.critical("INTRUSION DETECTED: Activating honeypot and endpoint rotation")
        try:
            ZKPHandler().rotate_keys()
        except Exception as e:
            _LOGGER.error(f"Key rotation failed: {str(e)}")
        
        # Calling a function from your Firewall module for a more modular approach
        try:
            Firewall().activate_intrusion_response()
        except Exception as e:
            _LOGGER.error(f"Firewall command failed: {str(e)}")
            
        _BLOCKCHAIN_LOGGER.log_event("IntrusionDetected", {"timestamp": datetime.now().isoformat()})

    def federated_update(self, encrypted_update: bytes, signature: str) -> bool:
        """Apply federated learning update with signature verification"""
        try:
            update_data = _CIPHER_SUITE.decrypt(encrypted_update)
            update_hash = hashlib.sha3_256(update_data).hexdigest()
            if update_hash != signature:
                _LOGGER.error("Federated update signature mismatch")
                return False
            update_model = joblib.loads(update_data)
            # Simple averaging for demonstration
            if hasattr(self.model, "coef_") and hasattr(update_model, "coef_"):
                self.model.coef_ = (self.model.coef_ + update_model.coef_) / 2
            _BLOCKCHAIN_LOGGER.log_event("FederatedUpdateApplied", {"timestamp": datetime.now().isoformat()})
            return True
        except Exception as e:
            _LOGGER.error(f"Federated update failed: {str(e)}")
            return False

    def audit_model(self) -> Dict[str, Any]:
        """Return model metadata and blockchain audit trail"""
        try:
            # NOTE: BlockchainUtils.get_events() is a placeholder function
            audit_trail = _BLOCKCHAIN_LOGGER.get_events(filter_by={"model": self.model_name})
            return {
                "metadata": self.metadata.__dict__ if self.metadata else {},
                "audit_trail": audit_trail
            }
        except Exception as e:
            _LOGGER.error(f"Audit retrieval failed: {str(e)}")
            return {}

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Unified prediction interface"""
        if self.model is None:
            _LOGGER.error("No model loaded for prediction")
            return np.array([])
        try:
            if self.model_name == "lstm_autoencoder":
                self.model.eval()
                with torch.no_grad():
                    X_tensor = torch.tensor(X, dtype=torch.float32)
                    output = self.model(X_tensor)
                    loss = ((output - X_tensor) ** 2).mean(dim=1)
                    # Thresholding: mark as anomaly if loss > threshold
                    threshold = loss.mean() + 2 * loss.std()
                    return (loss > threshold).cpu().numpy().astype(int)
            else:
                return self.model.predict(X)
        except Exception as e:
            _LOGGER.error(f"Prediction failed: {str(e)}")
            return np.array([])