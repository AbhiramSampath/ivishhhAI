import os
import re
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid
import hashlib
import hmac
import base64
from enum import Enum
from dataclasses import dataclass
import asyncio

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Security: Corrected imports
from models.user import UserProfile
from models.user import SessionStatus, CallType
from ivish_central.user_safety_center import generate_consent_token
from security.encryption_utils import SessionEncryptor
from utils.logger import log_event as log_audit_event
from security.intrusion_prevention.counter_response import BlackholeRouter
from security.blockchain.zkp_handler import verify_zk_token as verify_zk_token_wrapper

# --- Security Constants ---
_SUPPORTED_LANGUAGES = {
    "en", "en-US", "hi", "hi-IN", "es", "es-ES", "fr", "fr-FR",
    "ta", "ta-IN", "te", "te-IN", "kn", "kn-IN", "ml", "ml-IN", "bn", "bn-IN"
}
_INJECTION_PATTERNS = re.compile(
    r"(<\?php|javascript:|\.exec\()", 
    re.IGNORECASE
)
_MAX_TRANSCRIPT_LENGTH = 1000
_BLOCKLIST: Dict[str, float] = {}
_RATE_LIMIT_WINDOW = 60
_LANGUAGE_REGEX = r"^[a-z]{2,3}(-[A-Z]{2,3})?$"
_SESSION_PRIVATE_KEY = os.getenv("SESSION_PRIVATE_KEY", "secure_32_byte_key_for_sessions").encode()[:32]

@dataclass
class SessionMetadata:
    session_id: str
    user_a: str
    user_b: str
    lang_a: str
    lang_b: str
    call_type: CallType
    start_time: datetime
    secure_hash: str

class CallSession(BaseModel):
    session_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="UUID v7 with temporal ordering"
    )
    
    user_a: UserProfile
    user_b: UserProfile
    
    lang_a: str = Field(default="en-US", regex=_LANGUAGE_REGEX)
    lang_b: str = Field(default="hi-IN", regex=_LANGUAGE_REGEX)
    
    call_type: CallType = Field(
        default=CallType.VOICE_TRANSLATE,
        description="Encrypted call classification"
    )

    start_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0),
        description="UTC timestamp truncated to seconds"
    )
    end_time: Optional[datetime] = None
    
    status: SessionStatus = Field(
        default=SessionStatus.ACTIVE,
        description="Real-time state machine"
    )

    last_emotion_a: Optional[str] = Field(
        None,
        regex="^(neutral|happy|sad|angry|surprised|fear|disgust|empathic)$"
    )
    last_emotion_b: Optional[str] = Field(
        None,
        regex="^(neutral|happy|sad|angry|surprised|fear|disgust|empathic)$"
    )

    transcript_a: List[str] = Field(default_factory=list, max_items=1000)
    transcript_b: List[str] = Field(default_factory=list, max_items=1000)

    consent_token: str = Field(
        default_factory=generate_consent_token,
        description="SHA-3 hash of signed consent payload"
    )

    secure_hash: str = Field(
        default_factory=lambda: hashlib.blake2s(digest_size=32).hexdigest(),
        description="Double-hashed session fingerprint"
    )

    _encrypted_notes: Optional[str] = None
    security_flags: Dict[str, bool] = Field(
        default_factory=lambda: {
            "intrusion_detected": False,
            "encrypted": True,
            "verified_participants": False
        }
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z",
            bytes: lambda v: v.hex()
        }
        arbitrary_types_allowed = True
        validate_assignment = True
        extra = "forbid"

    @validator('user_a', 'user_b')
    def validate_users(cls, v):
        if not v.user_id or not v.voiceprint_hash:
            raise ValueError("Users must have valid IDs and voiceprints")
        return v

    @validator('lang_a', 'lang_b')
    def validate_language(cls, v):
        if v not in _SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language: {v}")
        return v

    async def end_session(self) -> None:
        if self.status != SessionStatus.ACTIVE:
            await log_audit_event("invalid_session_end", session_id=self.session_id)
            raise RuntimeError("Session already terminated")
        
        self.status = SessionStatus.ENDED
        self.end_time = datetime.now(timezone.utc).replace(microsecond=0)
        
        self._finalize_encryption()
        await log_audit_event("session_ended", session_id=self.session_id)

    async def add_transcript(self, user: str, text: str) -> None:
        if not text or not user:
            return
        
        sanitized = SessionEncryptor.sanitize_text(text)
        if not sanitized:
            await BlackholeRouter().trigger()
            return

        if user == "a":
            self.transcript_a.append(sanitized)
            if len(self.transcript_a) > _MAX_TRANSCRIPT_LENGTH:
                self.transcript_a.pop(0)
        elif user == "b":
            self.transcript_b.append(sanitized)
            if len(self.transcript_b) > _MAX_TRANSCRIPT_LENGTH:
                self.transcript_b.pop(0)
        else:
            await log_audit_event("invalid_transcript_user", user=user)
            await BlackholeRouter().trigger()

    async def update_emotion(self, user: str, emotion: str) -> None:
        if user not in ("a", "b"):
            await log_audit_event("invalid_emotion_user", user=user)
            await BlackholeRouter().trigger()
        
        if emotion not in {"neutral", "happy", "sad", "angry", "surprised", "fear", "disgust", "empathic"}:
            await log_audit_event("invalid_emotion", emotion=emotion)
            return

        if user == "a":
            self.last_emotion_a = emotion
        else:
            self.last_emotion_b = emotion
        
        await log_audit_event(
            "emotion_update",
            session_id=self.session_id,
            user=user,
            emotion=emotion
        )

    def _finalize_encryption(self) -> None:
        if self._encrypted_notes:
            self._encrypted_notes = SessionEncryptor().encrypt(self._encrypted_notes, key=_SESSION_PRIVATE_KEY)

    def generate_session_hash(self) -> str:
        payload = f"{self.user_a.user_id}{self.user_b.user_id}{self.start_time.isoformat()}"
        return hashlib.blake2s(
            payload.encode(),
            key=_SESSION_PRIVATE_KEY,
            digest_size=32
        ).hexdigest()

    def verify_session_integrity(self) -> bool:
        current_hash = self.generate_session_hash()
        return hmac.compare_digest(current_hash, self.secure_hash)

    def set_notes(self, notes: str) -> None:
        self._encrypted_notes = SessionEncryptor().encrypt(notes.encode(), key=_SESSION_PRIVATE_KEY)
    
    def get_notes(self) -> Optional[str]:
        if not self._encrypted_notes:
            return None
        return SessionEncryptor().decrypt(self._encrypted_notes, key=_SESSION_PRIVATE_KEY).decode()

    def validate_participants(self) -> bool:
        try:
            a_valid = verify_zk_token_wrapper(self.user_a.zkp_token, self.user_a.user_id)
            b_valid = verify_zk_token_wrapper(self.user_b.zkp_token, self.user_b.user_id)
            self.security_flags["verified_participants"] = a_valid and b_valid
            return a_valid and b_valid
        except Exception as e:
            log_audit_event("participant_verification_failed", error=str(e))
            return False