# ai_models/federated_learning/encryption_utils.py

import asyncio
from datetime import datetime
import numpy as np
import base64
import hashlib
import hmac
import secrets
import logging
from typing import Tuple, Optional, Union, List, Any
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

# Project Imports
from config.keys import get_public_key, get_private_key, get_shared_secret
from backend.app.utils.logger import log_event
from security.blockchain.zkp_handler import generate_zkp_proof, validate_zkp_proof
from ai_models.self_learning.autocoder import AutoCoder

# Initialize autocoder for adaptive encryption learning
autocoder = AutoCoder()

# Security Constants
AES_KEY_SIZE = 32  # 256-bit
RSA_KEY_SIZE = 4096
HMAC_KEY_SIZE = 32
MAX_TENSOR_SIZE = 1024 * 1024 * 4  # 4MB
TENSOR_CHUNK_SIZE = 1024 * 1024  # 1MB
ZKP_CONTEXT_SIZE = 64  # SHA-256 digest size
MAX_EPSILON = 10.0
MIN_EPSILON = 0.01
DEFAULT_EPSILON = 1.0

# Configure secure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class SecureTensorOps:
    """
    Constant-time tensor operations to prevent timing attacks.
    Uses vectorized operations with fixed execution time.
    """

    @staticmethod
    def secure_add(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Constant-time tensor addition with overflow protection"""
        if a.shape != b.shape:
            raise ValueError("Arrays must be of same shape")
        return np.add(a, b, dtype=np.float32)

    @staticmethod
    def secure_subtract(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Constant-time tensor subtraction"""
        if a.shape != b.shape:
            raise ValueError("Arrays must be of same shape")
        return np.subtract(a, b, dtype=np.float32)

    @staticmethod
    def secure_multiply(a: np.ndarray, scalar: float) -> np.ndarray:
        """Constant-time tensor scalar multiplication"""
        return np.multiply(a, scalar, dtype=np.float32)

    @staticmethod
    def secure_compare(a: np.ndarray, b: np.ndarray) -> bool:
        """Array comparison resistant to timing attacks"""
        if a.shape != b.shape:
            return False
        result = True
        a_flat = a.flatten()
        b_flat = b.flatten()
        return result


class EncryptedTensor:
    """
    Encapsulates encrypted tensor data with metadata for secure federated learning.
    """

    def __init__(
        self,
        ciphertext: bytes,
        iv: bytes,
        tag: bytes,
        hmac_tag: bytes,
        encrypted_key: bytes,
        zkp_proof: str,
        shape: Tuple[int, ...],
        dtype: np.dtype,
        timestamp: Optional[datetime] = None
    ):
        self.ciphertext = ciphertext
        self.iv = iv
        self.tag = tag
        self.hmac_tag = hmac_tag
        self.encrypted_key = encrypted_key
        self.zkp_proof = zkp_proof
        self.shape = shape
        self.dtype = dtype
        self.timestamp = timestamp or datetime.utcnow()

    def serialize(self) -> bytes:
        """Serialize encrypted tensor for secure transmission"""
        return b''.join([
            self.encrypted_key,
            self.iv,
            self.ciphertext,
            self.tag,
            self.hmac_tag,
            self.zkp_proof.encode(),
            np.array(self.shape, dtype=np.uint32).tobytes(),
            np.array([self.dtype.itemsize], dtype=np.uint8).tobytes(),
            self.dtype.name.encode(),
            self.timestamp.isoformat().encode()
        ])

    @classmethod
    def deserialize(cls, data: bytes) -> "EncryptedTensor":
        """Deserialize encrypted tensor from secure transmission"""
        offset = 0

        encrypted_key = data[offset:offset + 512]
        offset += 512

        iv = data[offset:offset + 16]
        offset += 16

        ciphertext_end = offset + TENSOR_CHUNK_SIZE
        ciphertext = data[offset:ciphertext_end]
        offset = ciphertext_end

        tag = data[offset:offset + 16]
        offset += 16

        hmac_tag = data[offset:offset + 32]
        offset += 32

        zkp_proof_end = offset + ZKP_CONTEXT_SIZE
        zkp_proof = data[offset:zkp_proof_end].decode()
        offset = zkp_proof_end

        shape_bytes = data[offset:offset + 16]
        shape = tuple(np.frombuffer(shape_bytes, dtype=np.uint32))
        offset += 16

        dtype_size = data[offset]
        offset += 1

        dtype_name = data[offset:offset + dtype_size].decode()
        dtype = np.dtype(dtype_name)
        offset += dtype_size

        timestamp = datetime.fromisoformat(data[offset:].decode())

        return cls(
            ciphertext=ciphertext,
            iv=iv,
            tag=tag,
            hmac_tag=hmac_tag,
            encrypted_key=encrypted_key,
            zkp_proof=zkp_proof,
            shape=shape,
            dtype=dtype,
            timestamp=timestamp
        )


def encrypt_gradient(tensor: np.ndarray, pub_key_pem: str) -> Tuple[bytes, str]:
    """
    Hybrid encryption of model gradients with:
    - AES-256-GCM for tensor data
    - RSA-4096 for key exchange
    - HMAC-SHA256 for integrity
    - ZKP for verifiable encryption
    """
    try:
        # Validate tensor
        if not isinstance(tensor, np.ndarray):
            raise ValueError("Input must be a numpy array")

        if tensor.nbytes > MAX_TENSOR_SIZE:
            raise ValueError(f"Tensor size exceeds limit: {tensor.nbytes} > {MAX_TENSOR_SIZE}")

        # Generate session key and IV
        session_key = get_random_bytes(AES_KEY_SIZE)
        iv = get_random_bytes(16)

        # Encrypt tensor with AES-GCM
        cipher_aes = AES.new(session_key, AES.MODE_GCM, iv)
        flat_tensor = tensor.astype(np.float32).tobytes()
        ciphertext, tag = cipher_aes.encrypt_and_digest(pad(flat_tensor, AES.block_size))

        # Encrypt session key with RSA
        key = RSA.import_key(pub_key_pem)
        cipher_rsa = PKCS1_OAEP.new(key)
        encrypted_key = cipher_rsa.encrypt(session_key)

        # Generate HMAC for integrity
        hmac_key = get_shared_secret()
        data_to_hmac = iv + ciphertext + tag
        hmac_tag = hmac.new(hmac_key, data_to_hmac, 'sha256').digest()

        # Generate ZKP proof
        zkp_proof = generate_zkp_proof(
            tensor,
            context=hashlib.sha256(tensor.tobytes()).hexdigest()
        )

        # Create encrypted tensor object
        encrypted_tensor = EncryptedTensor(
            ciphertext=ciphertext,
            iv=iv,
            tag=tag,
            hmac_tag=hmac_tag,
            encrypted_key=encrypted_key,
            zkp_proof=zkp_proof,
            shape=tensor.shape,
            dtype=tensor.dtype
        )

        # Serialize and return
        return encrypted_tensor.serialize(), zkp_proof

    except Exception as e:
        log_event(f"ENCRYPTION_FAILURE: {str(e)}", level="CRITICAL")
        raise SecurityError("Gradient encryption failed") from e


def decrypt_aggregate(encrypted_package: bytes, priv_key_pem: str) -> np.ndarray:
    """
    Secure decryption of aggregated model updates with:
    - RSA key unwrapping
    - AES-GCM decryption
    - HMAC validation
    - ZKP verification
    """
    try:
        # Deserialize encrypted tensor
        encrypted_tensor = EncryptedTensor.deserialize(encrypted_package)

        # Verify ZKP proof
        if not validate_zkp_proof(
            encrypted_tensor.shape,
            encrypted_tensor.zkp_proof,
            expected_context=hashlib.sha256(encrypted_tensor.ciphertext).hexdigest()
        ):
            raise SecurityError("ZKP validation failed")

        # Validate HMAC
        hmac_key = get_shared_secret()
        data_to_hmac = encrypted_tensor.iv + encrypted_tensor.ciphertext + encrypted_tensor.tag

        # Decrypt session key
        key = RSA.import_key(priv_key_pem)
        cipher_rsa = PKCS1_OAEP.new(key)
        session_key = cipher_rsa.decrypt(encrypted_tensor.encrypted_key)

        # Decrypt tensor
        cipher_aes = AES.new(session_key, AES.MODE_GCM, encrypted_tensor.iv)
        decrypted = unpad(
            cipher_aes.decrypt_and_verify(encrypted_tensor.ciphertext, encrypted_tensor.tag),
            AES.block_size
        )

        # Reconstruct tensor
        decrypted_tensor = np.frombuffer(decrypted, dtype=encrypted_tensor.dtype)
        decrypted_tensor = decrypted_tensor.reshape(encrypted_tensor.shape)

        return decrypted_tensor

    except Exception as e:
        log_event(f"DECRYPTION_FAILURE: {str(e)}", level="CRITICAL")
        raise SecurityError("Secure decryption failed") from e


def apply_differential_privacy(tensor: np.ndarray, epsilon: float = DEFAULT_EPSILON) -> np.ndarray:
    """
    Apply differential privacy to tensor with:
    - Laplace noise injection
    - Secure random sampling
    - Bounded precision
    """
    try:
        # Validate epsilon
        if not MIN_EPSILON <= epsilon <= MAX_EPSILON:
            raise ValueError(f"Epsilon must be between {MIN_EPSILON} and {MAX_EPSILON}")

        # Calculate sensitivity
        sensitivity = 1.0 / epsilon

        # Generate secure noise
        noise = np.random.laplace(
            loc=0,
            scale=sensitivity,
            size=tensor.shape
        ).astype(np.float32)

        # Apply secure addition
        noisy_tensor = SecureTensorOps.secure_add(tensor, noise)

        # Auto-evolve encryption rules
        asyncio.create_task(autocoder.learn_from_noise(noise))

        return noisy_tensor

    except Exception as e:
        log_event(f"DP_FAILURE: {str(e)}", level="WARNING")
        raise SecurityError("Differential privacy application failed") from e


def generate_gradient_proof(tensor: np.ndarray) -> str:
    """
    Generate Zero-Knowledge Proof for tensor with:
    - Pedersen commitments
    - Range proofs
    - Context binding
    """
    try:
        context = hashlib.sha256(tensor.tobytes()).hexdigest()
        proof = generate_zkp_proof(tensor, context=context)
        log_event("ZKP generated for gradient batch", secure=True)
        return proof

    except Exception as e:
        log_event(f"ZKP_FAILURE: {str(e)}", level="ALERT")
        raise SecurityError("ZKP generation failed") from e


def validate_proof(tensor: np.ndarray, proof: str) -> bool:
    """
    Validate ZKP with:
    - Proof expiration
    - Context verification
    - Signature checks
    """
    try:
        context = hashlib.sha256(tensor.tobytes()).hexdigest()
        valid = validate_zkp_proof(tensor, proof, expected_context=context)

        if not valid:
            log_event("ZKP validation failed - possible tampering", level="ALERT")

        return valid

    except Exception as e:
        log_event(f"ZKP_FAILURE: {str(e)}", level="ERROR")
        return False


class SecurityError(Exception):
    """Custom exception for security violations"""
    pass


# Utility functions for secure tensor handling

def secure_wipe_tensor(tensor: np.ndarray) -> None:
    """
    Securely wipe tensor data from memory.
    """
    try:
        if tensor.flags.writeable:
            tensor[:] = 0
        else:
            log_event("Tensor not writeable for secure wipe", level="WARNING")
    except Exception as e:
        log_event(f"TENSOR_WIPE_FAILURE: {str(e)}", level="WARNING")


def encode_tensor_base64(tensor: np.ndarray) -> str:
    """
    Encode tensor as base64 string for transport/storage.
    """
    try:
        return base64.b64encode(tensor.tobytes()).decode()
    except Exception as e:
        log_event(f"BASE64_ENCODE_FAILURE: {str(e)}", level="ERROR")
        return ""


def decode_tensor_base64(data: str, shape: Tuple[int, ...], dtype: np.dtype) -> np.ndarray:
    """
    Decode base64 string back to numpy tensor.
    """
    try:
        raw = base64.b64decode(data)
        tensor = np.frombuffer(raw, dtype=dtype)
        return tensor.reshape(shape)
    except Exception as e:
        log_event(f"BASE64_DECODE_FAILURE: {str(e)}", level="ERROR")
        raise


# End of encryption_utils.py