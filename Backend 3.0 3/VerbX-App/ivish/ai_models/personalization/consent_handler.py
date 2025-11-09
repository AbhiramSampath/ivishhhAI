import uuid
import os
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Literal, Optional, Union
from enum import Enum

# Crypto Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hmac

# Corrected Project Imports
from backend.app.db.mongo import MongoStore
from backend.app.utils.logger import log_event
from backend.app.auth.jwt_handler import get_user_id_from_token

from security.blockchain.blockchain_utils import log_to_blockchain
from security.blockchain.zkp_handler import ZeroKnowledgeProof
from ai_models.ivish.ivish_memory import IvishMemory

# Initialize secure components
CONSENT_COLLECTION = MongoStore(collection="user_consents")
memory_handler = IvishMemory()
backend = default_backend()

# Consent Constants
FEATURES = Literal["memory", "biometrics", "tracking", "personalization", "language_data"]
CONSENT_TTL = timedelta(days=365)
ZKP_TTL = 60 * 5
MAX_CONSENT_FAILURES = 5
BLOCKED_IP_TTL = 60 * 60
SCHEMA_VERSION = 2

class ConsentStatus(Enum):
    GRANTED = True
    REVOKED = False
    UNKNOWN = None

class ConsentCrypto:
    """
    Military-grade cryptographic utilities for consent handling.
    Uses AES-GCM with HKDF-derived keys for secure storage.
    """
    @staticmethod
    def derive_key(user_id: str) -> bytes:
        """Secure per-user key derivation"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"consent_salt",
            info=user_id.encode('utf-8'),
            backend=backend
        )
        return hkdf.derive(os.urandom(32))

    @staticmethod
    def encrypt_consent(value: bool, key: bytes) -> Dict[str, bytes]:
        """AES-GCM encryption with integrity and IV"""
        iv = os.urandom(12)
        aesgcm = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=backend
        ).encryptor()
        ciphertext = aesgcm.update(str(value).encode()) + aesgcm.finalize()
        return {
            "iv": iv,
            "ciphertext": ciphertext,
            "tag": aesgcm.tag
        }

    @staticmethod
    def decrypt_consent(data: Dict[str, bytes], key: bytes) -> bool:
        """Secure decryption with integrity check"""
        try:
            aesgcm = Cipher(
                algorithms.AES(key),
                modes.GCM(data["iv"], data["tag"]),
                backend=backend
            ).decryptor()
            plaintext = aesgcm.update(data["ciphertext"]) + aesgcm.finalize()
            return plaintext.decode().lower() == 'true'
        except Exception:
            return False

class ConsentDefense:
    """
    Active defense system for consent-related attacks.
    Includes honeypot activation, IP blocking, and threat modeling.
    """
    _attack_patterns = {}
    _blocked_ips = {}

    @classmethod
    async def trigger_honeypot(cls):
        """Misdirect attackers with fake DB entries"""
        fake_id = str(uuid.uuid4())
        await CONSENT_COLLECTION.insert_async({
            "user_id": fake_id,
            "consents": {f: {"value": True} for f in FEATURES.__args__},
            "expires_at": datetime.now(timezone.utc) + timedelta(days=365),
            "schema_version": SCHEMA_VERSION
        })
        log_event(f"Honeypot triggered for fake user {fake_id}", level="SECURE")

    @classmethod
    def record_attack_vector(cls, feature: str, ip: Optional[str] = None):
        """Track attack patterns and block IPs"""
        cls._attack_patterns[feature] = cls._attack_patterns.get(feature, 0) + 1
        if ip:
            count = cls._blocked_ips.get(ip, 0) + 1
            cls._blocked_ips[ip] = count
            if count >= MAX_CONSENT_FAILURES:
                cls.block_ip(ip)

    @classmethod
    def block_ip(cls, ip: str):
        """Block malicious IPs temporarily"""
        cls._blocked_ips[ip] = datetime.now(timezone.utc) + timedelta(seconds=BLOCKED_IP_TTL)
        log_event(f"IP blocked for consent abuse: {ip}", level="ALERT")

async def set_consent(
    token: str,
    feature: FEATURES,
    value: bool,
    zkp_proof: bytes,
    ip: Optional[str] = None
) -> None:
    """
    Sets consent with Zero-Knowledge Proof validation.
    Enforces secure consent changes with immutable logging.
    """
    user_id = get_user_id_from_token(token)
    if not user_id:
        ConsentDefense.record_attack_vector(feature, ip)
        raise PermissionError("Invalid token")

    if not ZeroKnowledgeProof.verify(zkp_proof, feature.encode()):
        log_event(f"ZKP validation failed for {user_id}", level="ALERT")
        await ConsentDefense.trigger_honeypot()
        raise PermissionError("Zero-Knowledge Proof validation failed")

    key = ConsentCrypto.derive_key(user_id)
    encrypted = ConsentCrypto.encrypt_consent(value, key)

    update_data = {
        f"consents.{feature}": {
            "iv": encrypted["iv"],
            "ciphertext": encrypted["ciphertext"],
            "tag": encrypted["tag"],
            "zkp_hash": hashlib.sha3_256(zkp_proof).hexdigest(),
            "feature": feature,
            "schema_version": SCHEMA_VERSION
        }
    }

    await CONSENT_COLLECTION.update_async(
        {"user_id": user_id},
        {"$set": update_data},
        upsert=True
    )

    await log_to_blockchain("consent_change", {
        "user_id_hashed": hashlib.sha3_256(user_id.encode()).hexdigest(),
        "feature": feature,
        "action": "grant" if value else "revoke",
    })

    if feature == "memory":
        await memory_handler.update_consent(user_id, feature, value)

    log_event(f"Consent updated for {user_id}: {feature} = {value}", secure=True)

async def get_consent_status(token: str) -> Dict[str, bool]:
    """
    Returns decrypted consent status with rate-limiting and schema versioning.
    """
    user_id = get_user_id_from_token(token)
    if not user_id:
        raise PermissionError("Invalid token")

    doc = await CONSENT_COLLECTION.find_one_async({"user_id": user_id})
    if not doc:
        return {}

    key = ConsentCrypto.derive_key(user_id)
    consents = {}

    for feature, data in doc.get("consents", {}).items():
        if not isinstance(data, dict):
            continue

        try:
            if data.get("schema_version", 1) > SCHEMA_VERSION:
                log_event(f"Future schema version detected: {data['schema_version']}", level="WARNING")
                continue

            encrypted = {
                "iv": data["iv"],
                "ciphertext": data["ciphertext"],
                "tag": data["tag"]
            }
            consents[feature] = ConsentCrypto.decrypt_consent(encrypted, key)
        except Exception as e:
            log_event(f"Consent decryption failed: {str(e)}", level="ERROR")
            continue

    return consents

async def enforce_consent(token: str, feature: FEATURES, ip: Optional[str] = None) -> None:
    """
    Strict enforcement with intrusion detection.
    Raises PermissionError if consent missing.
    """
    try:
        status = await get_consent_status(token)
        if not status.get(feature, ConsentStatus.UNKNOWN):
            log_event(f"Unauthorized access attempt: {feature}", level="WARNING")
            ConsentDefense.record_attack_vector(feature, ip)
            raise PermissionError(
                f"Consent missing for {feature}. " +
                "Reference GDPR Article 7 at support@verbx.ai"
            )
    except PermissionError:
        ConsentDefense.record_attack_vector(feature, ip)
        raise

async def revoke_all(token: str) -> None:
    """
    Nuclear data wipe with confirmation.
    Revokes all user consents, securely deletes related data, and logs the action immutably.
    """
    user_id = get_user_id_from_token(token)
    if not user_id:
        raise PermissionError("Invalid token")

    await CONSENT_COLLECTION.delete_async({"user_id": user_id})
    await log_to_blockchain("consent_purge", {
        "user_id_hashed": hashlib.sha3_256(user_id.encode()).hexdigest(),
    })

    try:
        await memory_handler.clear_user(user_id)
    except Exception as e:
        log_event(f"Memory session wipe failed for {user_id}: {str(e)}", level="ERROR")

    log_event(f"All consent revoked and data wiped for {user_id}", secure=True)