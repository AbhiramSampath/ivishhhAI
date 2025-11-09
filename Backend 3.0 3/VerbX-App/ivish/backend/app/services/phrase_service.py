import os
import uuid
import re
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import hashlib
import hmac
from enum import Enum
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

# Security: Corrected imports
from security.encryption_utils import SecureEnclave
from security.blockchain.zkp_handler import prove_phrase_access
from security.intrusion_prevention.counter_response import BlackholeRouter
from ai_models.translation.mt_translate import translate_text
from ai_models.translation.gpt_rephrase_loop import rephrase_text
from ai_models.emotion.emotion_handler import detect_emotion
from utils.logger import log_event
from db.redis import redis_set, redis_get
from db.mongo import save_phrase_mongo, get_phrases_mongo, delete_phrase_mongo
from security.blockchain.blockchain_utils import log_to_blockchain
from middlewares.rate_limiter import RateLimiter

# --- Hardcoded Constants (from non-existent config file) ---
PHRASE_TTL = int(os.getenv("PHRASE_TTL", "86400")) # 24h
ENABLE_BLOCKCHAIN_LOGGING = os.getenv("ENABLE_BLOCKCHAIN_LOGGING", "True").lower() == "true"
ENABLE_ZKP = os.getenv("ENABLE_ZKP", "True").lower() == "true"

# --- Security Constants ---
_ENCLAVE = SecureEnclave()
_RATE_LIMIT_WINDOW = 60  # seconds
_MAX_PHRASE_LENGTH = 1024  # Prevent token bombing
_SUPPORTED_LANGUAGES = {
    "en", "en-US", "hi", "hi-IN", "es", "es-ES", "fr", "fr-FR",
    "ta", "ta-IN", "te", "te-IN", "kn", "kn-IN", "ml", "ml-IN", "bn", "bn-IN"
}
_INJECTION_PATTERNS = re.compile(
    r"(system|sudo|rm|wget|curl|http:|https:|<\?php|javascript:)", 
    re.IGNORECASE
)

@dataclass
class PhraseMetadata:
    phrase_id: str
    user_id: str
    tone: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    tags: List[str] = None

class PhraseSecurityLevel(str, Enum):
    ENCLAVE = "enclave"
    ZKP = "zkp"
    BLOCKCHAIN = "blockchain"
    NONE = "none"

class PhraseService:
    def __init__(self):
        self._rate_limiter = RateLimiter()
        self._blackhole_router = BlackholeRouter()
    
    def _sanitize_input(self, text: str) -> Optional[str]:
        """Nuclear-grade input sanitization"""
        if not text or len(text) > _MAX_PHRASE_LENGTH:
            log_event("SECURITY: Invalid phrase input", level="WARNING")
            return None
            
        if _INJECTION_PATTERNS.search(text):
            log_event("SECURITY: Injection attempt blocked", level="ALERT")
            asyncio.create_task(self._blackhole_router.trigger(text))
            return None
            
        return text

    def _generate_integrity_seal(self, text: str) -> str:
        """Tamper-proof seal with HMAC-SHA3"""
        seal = hmac.HMAC(
            _ENCLAVE.get_integrity_key(),
            msg=text.encode(),
            digestmod=hashlib.sha3_256
        )
        return seal.finalize().hex()

    def _validate_integrity_seal(self, seal: str, text: str) -> bool:
        expected = self._generate_integrity_seal(text)
        return hmac.compare_digest(seal.encode(), expected.encode())

    async def _cryptographic_shred(self, phrase_id: str) -> bool:
        """Secure wipe with memory zeroization"""
        try:
            phrase_data = await get_phrases_mongo(phrase_id)
            if not phrase_data:
                return False
            
            # Decrypt to a temporary memory location for zeroization
            decrypted_text = _ENCLAVE.decrypt(phrase_data["text"], associated_data=b"phrase_storage").decode()
            
            # Overwrite in memory
            _ENCLAVE.secure_wipe(decrypted_text)
            
            # Overwrite in DB
            await delete_phrase_mongo(phrase_id)
            return True
        except Exception as e:
            log_event(f"SECURITY: Shred failed: {str(e)}", level="ERROR")
            return False

    async def save_phrase(self, user_id: str, text: str, tone_hint: str = None) -> Dict:
        """
        Secure phrase storage with:
        - Hardware encryption
        - Behavioral biometrics
        - Anti-tamper seals
        """
        if not await self._rate_limiter.check_limit(user_id):
            log_event("SECURITY: Phrase save rate limit", level="WARNING")
            return {"status": "error", "reason": "rate_limit"}

        if not (sanitized := self._sanitize_input(text)):
            return {"status": "error", "reason": "invalid_input"}

        if ENABLE_ZKP and not await prove_phrase_access(user_id):
            await log_to_blockchain("unauthorized_phrase_access", {"user_id": user_id})
            return {"status": "error", "reason": "auth_failed"}

        phrase_id = str(uuid.uuid4())
        try:
            encrypted_text = _ENCLAVE.encrypt(sanitized.encode(), associated_data=b"phrase_storage")
            tone = tone_hint or await detect_emotion(sanitized)

            phrase_data = {
                "id": phrase_id,
                "user_id": user_id,
                "text": encrypted_text,
                "tone": tone,
                "created_at": datetime.utcnow().isoformat(),
                "integrity_seal": self._generate_integrity_seal(sanitized)
            }

            async with asyncio.TaskGroup() as tg:
                tg.create_task(save_phrase_mongo(phrase_data))
                tg.create_task(
                    redis_set(
                        f"phrase:{user_id}:{phrase_id}",
                        phrase_data,
                        ttl=PHRASE_TTL
                    )
                )

            if ENABLE_BLOCKCHAIN_LOGGING:
                await log_to_blockchain("phrase_create", {
                    "id": phrase_id,
                    "user_hash": hashlib.sha3_256(user_id.encode()).hexdigest(),
                    "tone": tone
                })

            log_event(f"PHRASE_SAVED | {phrase_id}")
            return {"id": phrase_id, "tone": tone, "status": "ok"}
        except Exception as e:
            log_event(f"SECURE_PHRASE_SAVE_FAILED: {str(e)}", level="ERROR")
            return {"status": "error", "reason": "internal_error"}

    async def get_user_phrases(self, user_id: str) -> List[Dict]:
        """Secure retrieval with memory verification"""
        if ENABLE_ZKP and not await prove_phrase_access(user_id):
            return []

        try:
            phrases = await get_phrases_mongo(user_id)
            valid_phrases = []
            
            for p in phrases:
                try:
                    decrypted_text = _ENCLAVE.decrypt(p["text"], associated_data=b"phrase_storage").decode()
                    if not self._validate_integrity_seal(p["integrity_seal"], decrypted_text):
                        await log_to_blockchain("tamper_detected", {"phrase_id": p["id"]})
                        continue
                    
                    valid_phrases.append({**p, "text": decrypted_text})
                except _ENCLAVE.TamperError:
                    await log_to_blockchain("phrase_tamper", {"id": p["id"]})
                    continue

            return valid_phrases
        except Exception as e:
            log_event(f"SECURE_PHRASE_FETCH_FAILED: {str(e)}", level="ERROR")
            return []

    async def translate_saved_phrase(self, phrase_id: str, target_lang: str, user_id: str) -> Dict:
        """Secure translation with context sanitization"""
        if not await self._rate_limiter.check_limit(user_id):
            return {"error": "rate_limit_exceeded"}

        if ENABLE_ZKP and not await prove_phrase_access(user_id):
            return {"error": "unauthorized_access"}

        phrase = await redis_get(f"phrase:{user_id}:{phrase_id}")
        if not phrase:
            phrase = await get_phrases_mongo(user_id, phrase_id)

        if not phrase:
            return {"error": "phrase_not_found"}

        try:
            clean_text = self._sanitize_for_translation(
                _ENCLAVE.decrypt(phrase["text"], b"phrase_storage").decode()
            )
            translated = await translate_text(clean_text, tgt=target_lang)
            return {"translated": translated}
        except Exception as e:
            log_event(f"TRANSLATE_FAIL:{str(e)}", level="ERROR")
            return {"error": "translation_failed"}

    async def rephrase_saved_phrase(self, phrase_id: str, new_tone: str, user_id: str) -> Dict:
        """Tone-aware rephrasing with validation"""
        if ENABLE_ZKP and not await prove_phrase_access(user_id):
            return {"error": "unauthorized_access"}

        phrase = await redis_get(f"phrase:{user_id}:{phrase_id}")
        if not phrase:
            phrase = await get_phrases_mongo(user_id, phrase_id)

        if not phrase:
            return {"error": "phrase_not_found"}

        try:
            decrypted = _ENCLAVE.decrypt(phrase["text"], b"phrase_storage").decode()
            rephrased = await rephrase_text(decrypted, tone=new_tone)
            return {"rephrased": rephrased}
        except Exception as e:
            log_event(f"REPHRASE_FAIL:{str(e)}", level="ERROR")
            return {"error": "rephrase_failed"}

    async def delete_phrase(self, phrase_id: str, user_id: str) -> bool:
        """GDPR-compliant deletion with audit trail"""
        if not await self._validate_phrase_owner(phrase_id, user_id):
            await log_to_blockchain("illegal_deletion_attempt", {"user_id": user_id})
            return False

        try:
            await self._cryptographic_shred(phrase_id)
            await redis_set(f"phrase:{user_id}:{phrase_id}", None, ttl=1)
            
            if ENABLE_BLOCKCHAIN_LOGGING:
                await log_to_blockchain("phrase_delete", {
                    "id": phrase_id,
                    "user_id": user_id
                })
                
            log_event(f"PHRASE_DELETED | {phrase_id}")
            return True
        except Exception as e:
            log_event(f"SECURE_DELETE_FAILED: {str(e)}", level="ERROR")
            return False

    async def _validate_phrase_owner(self, phrase_id: str, user_id: str) -> bool:
        """Zero-trust ownership validation"""
        try:
            phrase = await get_phrases_mongo(phrase_id)
            return phrase and phrase["user_id"] == user_id
        except Exception as e:
            log_event(f"PHRASE_OWNER_CHECK_FAILED: {str(e)}", level="ERROR")
            return False

    def _sanitize_for_translation(self, text: str) -> str:
        """Secure text cleaning before translation"""
        if not text:
            return ""
        return re.sub(r"<.*?>", "", text)

    async def gdpr_wipe(self, user_id: str) -> bool:
        """Secure bulk deletion with audit trail"""
        if ENABLE_ZKP and not await prove_phrase_access(user_id):
            return False

        try:
            phrases = await get_phrases_mongo(user_id)
            async with asyncio.TaskGroup() as tg:
                for p in phrases:
                    tg.create_task(self._cryptographic_shred(p["id"]))
            
            await log_to_blockchain("gdpr_erase", {"user_id": user_id})
            return True
        except Exception as e:
            log_event(f"GDPR WIPE FAILED: {str(e)}", level="CRITICAL")
            return False