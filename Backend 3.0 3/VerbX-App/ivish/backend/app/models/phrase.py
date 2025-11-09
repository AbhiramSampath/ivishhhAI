from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import uuid
import hashlib
import re
import hmac
import os
import json
import asyncio
from enum import Enum
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# Security: Corrected imports
from security.security import sanitize_user_text
from security.encryption_utils import EncryptedStr
from utils.logger import log_event as log_audit_event
from security.intrusion_prevention.counter_response import BlackholeRouter
from security.blockchain.zkp_handler import verify_phrase_access
from security.blockchain.blockchain_utils import generate_consent_proof, validate_blockchain_proof

# --- Security Constants ---
_LANGUAGE_REGEX = re.compile(r"^[a-z]{2,3}(-[A-Z]{2,3})?$")
_PHRASE_ID_REGEX = re.compile(r"^phr_[a-f0-9]{32}$")
_USER_ID_REGEX = re.compile(r"^usr_[a-zA-Z0-9]{20}$")
_SESSION_ID_REGEX = re.compile(r"^sess_[a-f0-9]{32}$")
_SUPPORTED_LANGUAGES = {
    "en", "en-US", "hi", "hi-IN", "es", "es-ES", "fr", "fr-FR",
    "ta", "ta-IN", "te", "te-IN", "kn", "kn-IN", "ml", "ml-IN", "bn", "bn-IN"
}
_MAX_PHRASE_LENGTH = 1024
_BLOCKLIST: Dict[str, float] = {}
_RATE_LIMIT_WINDOW = 60
_INJECTION_PATTERNS = re.compile(r"(<\?php|javascript:|\.exec\()", re.IGNORECASE)
INTEGRITY_HASH_SECRET = os.getenv("INTEGRITY_HASH_SECRET", os.urandom(32)).encode()

class PhraseSource(str, Enum):
    USER = "user"
    GPT = "gpt"
    IMPORT = "import"
    LEARNING = "learning"

class ToneType(str, Enum):
    FORMAL = "formal"
    CASUAL = "casual"
    POLITE = "polite"
    ANGRY = "angry"
    HUMOROUS = "humorous"
    SARCASTIC = "sarcastic"

class EmotionType(str, Enum):
    HAPPY = "happy"
    SAD = "sad"
    ANGRY = "angry"
    SURPRISED = "surprised"
    NEUTRAL = "neutral"
    FEARFUL = "fearful"
    DISGUST = "disgust"

class Phrase(BaseModel):
    phrase_id: str = Field(
        default_factory=lambda: f"phr_{uuid.uuid4().hex}",
        regex=_PHRASE_ID_REGEX.pattern,
        description="Time-ordered UUID v7 for indexing"
    )
    
    user_id: str = Field(
        ...,
        regex=_USER_ID_REGEX.pattern,
        min_length=22,
        description="Strictly formatted user reference"
    )
    
    text: EncryptedStr = Field(
        ...,
        description="Original phrase with automatic encryption"
    )
    
    translation: Optional[EncryptedStr] = Field(
        None,
        description="Encrypted translated version"
    )
    
    language: str = Field(
        ...,
        regex=_LANGUAGE_REGEX.pattern,
        examples=["en", "fr-CA", "hi-IN"]
    )
    
    dialect: Optional[str] = Field(
        None,
        regex=r"^[A-Z][a-z]+(?:[ _-][A-Za-z]+)*$",
        examples=["Castilian", "Southern_American"]
    )
    
    tone: Optional[ToneType] = None
    emotion: Optional[EmotionType] = None
    
    source: PhraseSource = Field(
        default=PhraseSource.USER,
        description="Origin tracking for data lineage"
    )
    
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0),
        description="UTC timestamp truncated to seconds"
    )
    
    session_id: Optional[str] = Field(
        None,
        regex=_SESSION_ID_REGEX.pattern,
        description="Linked session for TTL purposes"
    )
    
    consent_given: bool = Field(
        default=False,
        description="Explicit user consent flag"
    )
    consent_verified_at: Optional[datetime] = None
    consent_proof: Optional[str] = Field(
        None,
        description="Blockchain transaction ID of consent record"
    )
    
    integrity_hash: str = Field(
        default_factory=lambda: hashlib.blake2s(digest_size=32).hexdigest(),
        description="Cryptographic phrase fingerprint"
    )

    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z",
            EncryptedStr: lambda v: v.get_encrypted()
        }
        arbitrary_types_allowed = True
        extra = "forbid"
        frozen = True

    @validator('text', 'translation', pre=True)
    def sanitize_text_fields(cls, v):
        if not v:
            return v
        
        if isinstance(v, str):
            if len(v) > _MAX_PHRASE_LENGTH:
                BlackholeRouter().trigger()
                return None
            
            if _INJECTION_PATTERNS.search(v):
                log_audit_event("phrase_injection_attempt", phrase=v[:30])
                return None
            
            return sanitize_user_text(v)
        return v

    @validator('language')
    def validate_language(cls, v):
        if not v or v not in _SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language: {v}")
        return v

    @root_validator(pre=True)
    def check_initial_access(cls, values):
        if not asyncio.run(verify_phrase_access(values.get("user_id"))):
            BlackholeRouter().trigger()
            raise PermissionError("Access denied")
        return values

    def generate_integrity_hash(self) -> str:
        payload = f"{self.user_id}{self.text.get_encrypted()}{self.created_at.isoformat()}"
        h = hmac.HMAC(INTEGRITY_HASH_SECRET, hashes.SHA3_256(), backend=default_backend())
        h.update(payload.encode())
        return h.finalize().hex()

    def verify_integrity(self) -> bool:
        expected_hash = self.generate_integrity_hash()
        return hmac.compare_digest(expected_hash.encode(), self.integrity_hash.encode())

    def verify_consent(self) -> bool:
        if not self.consent_given:
            return False
            
        if not self.consent_proof:
            self.consent_proof = generate_consent_proof(
                user_id=self.user_id,
                phrase_id=self.phrase_id
            )
            self.consent_verified_at = datetime.now(timezone.utc)
            
        return validate_blockchain_proof(self.consent_proof)

    def to_safe_dict(self) -> dict:
        return {
            "phrase_id": self.phrase_id,
            "language": self.language,
            "tone": self.tone,
            "emotion": self.emotion,
            "created_at": self.created_at,
            "integrity_hash": self.integrity_hash
        }

    def wipe_sensitive_data(self):
        if not self.consent_given:
            self.text = EncryptedStr(None)
            self.translation = EncryptedStr(None)
            log_audit_event("phrase_wiped", phrase_id=self.phrase_id, user_id=self.user_id)
        else:
            log_audit_event("phrase_wipe_denied", phrase_id=self.phrase_id, user_id=self.user_id)

    def __str__(self):
        return f"<Phrase {self.phrase_id} - {self.language}>"

    def __repr__(self):
        return self.__str__()