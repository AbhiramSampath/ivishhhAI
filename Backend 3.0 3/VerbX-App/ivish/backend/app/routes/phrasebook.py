# backend/app/routes/phrasebook.py

import uuid
import time
import hashlib
import hmac
import logging
import asyncio
import base64
import os
import json
from typing import Dict, List, Optional, Union, Any
from fastapi import APIRouter, Request, Depends, HTTPException, status, Security
from pydantic import BaseModel, Field, validator
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Project Imports - CORRECTED PATHS
from ..auth.jwt_handler import get_current_user
from backend.app.services.phrase_service import save_phrase, get_phrases, delete_phrase, clear_user_phrases
from utils.logger import log_event
from ivish_central.user_safety_center import check_memory_consent
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.translation.mt_translate import translate_text
from middlewares.rate_limiter import RateLimiter
from security.blockchain.blockchain_utils import log_to_blockchain
from ai_models.self_learning.autocoder import AutoCoder
from ai_models.ivish.memory_agent import MemorySessionHandler

# Initialize secure components
logger = logging.getLogger(__name__)
memory_handler = MemorySessionHandler()
autocoder = AutoCoder()
backend = default_backend()
rate_limiter = RateLimiter()

# Security Constants
_DEFAULT_KDF_ITERATIONS = int(os.getenv("PHRASEBOOK_KDF_ITERATIONS", 600000))
_DEFAULT_TTL_SESSION = int(os.getenv("PHRASEBOOK_TTL_SESSION", 12 * 60 * 60))
_DEFAULT_TTL_PERSISTENT = int(os.getenv("PHRASEBOOK_TTL_PERSISTENT", 90 * 24 * 60 * 60))
_MAX_PHRASE_LENGTH = 500
_MAX_TAGS = 5
_MIN_TAG_LENGTH = 1
_MAX_TAG_LENGTH = 20
_MIN_LANG_LENGTH = 2
_MAX_LANG_LENGTH = 5
_DEFAULT_HMAC_KEY = os.getenv("PHRASEBOOK_HMAC_KEY", os.urandom(32))
_DEFAULT_ENCRYPTION_KEY = os.getenv("PHRASE_ENCRYPTION_KEY", Fernet.generate_key().decode())

# Initialize phrasebook router
router = APIRouter(
    prefix="/phrasebook",
    tags=["Phrasebook"],
    dependencies=[Depends(Security(get_current_user, scopes=["phrasebook"]))]
)

# Phrasebook Encryption
class PhraseEncryptor:
    """
    Secure phrase encryption with:
    - User-derived keys
    - Fernet-based encryption
    - HMAC integrity validation
    """
    def __init__(self):
        self._fernet_cache = {}
        self._kdf_cache = {}

    def _derive_key(self, user_id: str) -> bytes:
        if user_id in self._kdf_cache:
            return self._kdf_cache[user_id]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"phrasebook_hmac_key", # Hardcoded salt for KDF
            iterations=_DEFAULT_KDF_ITERATIONS,
            backend=backend
        )
        key = base64.urlsafe_b64encode(kdf.derive(user_id.encode()))
        self._kdf_cache[user_id] = key
        return key

    def _get_fernet(self, user_id: str) -> Fernet:
        if user_id in self._fernet_cache:
            return self._fernet_cache[user_id]
        
        key = self._derive_key(user_id)
        self._fernet_cache[user_id] = Fernet(key)
        return self._fernet_cache[user_id]

    async def encrypt_phrase(self, user_id: str, text: str) -> str:
        try:
            cipher = self._get_fernet(user_id)
            return cipher.encrypt(text.encode()).decode()
        except Exception as e:
            log_event(f"PHRASEBOOK: Encryption failed - {str(e)}", level="ERROR")
            raise

    async def decrypt_phrase(self, user_id: str, encrypted: str) -> str:
        try:
            cipher = self._get_fernet(user_id)
            return cipher.decrypt(encrypted.encode()).decode()
        except Exception as e:
            log_event(f"PHRASEBOOK: Decryption failed - {str(e)}", level="WARNING")
            raise

encryptor = PhraseEncryptor()

class PhrasebookRouter:
    def __init__(self):
        self._router = APIRouter()
        self._router.add_api_route("/add", self.add_phrase, methods=["POST"])
        self._router.add_api_route("/list", self.list_phrases, methods=["GET"])
        self._router.add_api_route("/delete/{phrase_id}", self.delete_single_phrase, methods=["DELETE"])
        self._router.add_api_route("/clear", self.clear_all_phrases, methods=["DELETE"])
        
    @property
    def router(self):
        return self._router

    def _generate_signature(self, text: str, user_id: str) -> bytes:
        data = f"{text}:{user_id}:{time.time()}".encode()
        return hmac.new(_DEFAULT_HMAC_KEY, data, hashlib.sha256).digest()

    def _validate_phrase_integrity(self, phrase: Dict[str, Any]) -> bool:
        expected = self._generate_signature(phrase["text"], phrase["user_id"])
        return hmac.compare_digest(expected, phrase.get("signature", b''))

    async def add_phrase(
        self,
        data: PhraseInput,
        request: Request,
        user: Dict = Depends(get_current_user)
    ) -> Dict[str, Any]:
        user_id = user["id"]
        if not await rate_limiter.check_limit(user_id, rate=10, window=3600):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")

        if not await check_memory_consent(user_id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Memory consent not granted")

        phrase_id = str(uuid.uuid4())
        has_consent = await check_memory_consent(user_id)
        ttl = _DEFAULT_TTL_PERSISTENT if has_consent else _DEFAULT_TTL_SESSION

        try:
            encrypted_text = await encryptor.encrypt_phrase(user_id, data.text)
            encrypted_translation = await encryptor.encrypt_phrase(user_id, data.translation) if data.translation else None
        except Exception as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Phrase encryption failed")

        try:
            emotion = await detect_emotion(data.text[:500])
            lang = data.lang or await detect_language(data.text[:500])
        except Exception:
            emotion = "neutral"
            lang = "en"

        payload = {
            "user_id": user_id, "phrase_id": phrase_id, "text": encrypted_text,
            "translation": encrypted_translation, "tone": data.tone or emotion, "tags": data.tags,
            "lang": lang, "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(seconds=ttl),
            "ip": request.client.host,
            "user_agent": request.headers.get("user-agent", ""),
            "signature": self._generate_signature(data.text, user_id)
        }

        try:
            await save_phrase(payload)
            await log_to_blockchain("phrase_add", {"user_id": user_id, "phrase_id": phrase_id})
        except Exception as e:
            log_event(f"PHRASEBOOK: Save failed - {str(e)}", level="ERROR")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Phrasebook storage failed")

        return {"message": "Phrase saved", "phrase_id": phrase_id}

    async def list_phrases(
        self,
        user: Dict = Depends(get_current_user),
        lang: Optional[str] = None,
        tag: Optional[str] = None
    ) -> Dict[str, List[Dict]]:
        user_id = user["id"]
        if not await check_memory_consent(user_id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Memory consent not granted")

        encrypted_phrases = await get_phrases(user_id_hash=hashlib.sha256(user_id.encode()).hexdigest(), lang=lang, tag=tag)
        phrases = []
        for phrase in encrypted_phrases:
            try:
                decrypted_text = await encryptor.decrypt_phrase(user_id, phrase["text"])
                decrypted_translation = await encryptor.decrypt_phrase(user_id, phrase["translation"]) if phrase.get("translation") else None
                decrypted = {
                    **phrase,
                    "text": decrypted_text,
                    "translation": decrypted_translation
                }
                if self._validate_phrase_integrity(decrypted):
                    phrases.append(decrypted)
            except Exception as e:
                log_event(f"PHRASEBOOK: Decryption failed - {str(e)}", level="WARNING")
                continue
        return {"phrases": phrases}

    async def delete_single_phrase(self, phrase_id: str, user: Dict = Depends(get_current_user)) -> Dict[str, str]:
        user_id = user["id"]
        success = await delete_phrase(user_id_hash=hashlib.sha256(user_id.encode()).hexdigest(), phrase_id=phrase_id)
        if not success:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Phrase not found")
        await log_to_blockchain("phrase_delete", {"user_id": user_id, "phrase_id": phrase_id})
        return {"message": "Phrase deleted"}

    async def clear_all_phrases(self, user: Dict = Depends(get_current_user), confirm: bool = False) -> Dict[str, str]:
        if not confirm:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Confirmation required")
        user_id = user["id"]
        try:
            await clear_user_phrases(user_id_hash=hashlib.sha256(user_id.encode()).hexdigest())
            await log_to_blockchain("phrase_clear", {"user_id": user_id})
            return {"message": "All phrases deleted"}
        except Exception as e:
            log_event(f"PHRASEBOOK: Wipe failed - {str(e)}", level="ERROR")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Phrasebook wipe failed")

router = PhrasebookRouter().router

@router.get("/")
async def list_phrases_endpoint(user: dict = Depends(get_current_user)):
    return await PhrasebookRouter().list_phrases(user)
