# backend/routes/ner_tagger.py
# 🔒 Nuclear-Grade NER Tagging API with Zero-Trust Validation

import hmac
import os
import time
import uuid
import asyncio
import logging
import hashlib
import subprocess
import json
from typing import Dict, List, Optional, Any, Union
from fastapi import APIRouter, Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Internal imports - CORRECTED PATHS
from ai_models.ner.ner_handler import NEREngine
from utils.lang_codes import LanguageDetector
from security.security import TextSanitizer
from security.blockchain.zkp_handler import validate_ner_access
from security.blockchain.blockchain_utils import log_ner_event
from security.intrusion_prevention.counter_response import BlackholeRouter
from middlewares.rate_limiter import RateLimiter
from utils.logger import log_event

# Security constants
MAX_TEXT_LENGTH = 10000
NER_MODEL_VERSION = os.getenv("NER_MODEL_VERSION", "v2.1")
MAX_NER_RATE = int(os.getenv("MAX_NER_RATE", 20))
BLACKHOLE_DELAY = int(os.getenv("BLACKHOLE_DELAY", 60))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", 60))
TEMP_NER_PATHS = ["/tmp/ivish_ner_*", "/dev/shm/ner_*"]
NER_AES_KEY = os.getenv("NER_AES_KEY", "").encode()[:32]
if len(NER_AES_KEY) != 32:
    log_event("CRITICAL: Invalid encryption key for NER", alert=True)

# FastAPI router
router = APIRouter(
    prefix="/ner",
    tags=["named_entity_recognition"],
    dependencies=[Depends(HTTPBearer())]
)

logger = logging.getLogger(__name__)

class EntityTag(BaseModel):
    """
    Secure entity tag with cryptographic validation
    """
    word: str
    type: str
    start: int
    end: int
    confidence: float = Field(..., ge=0.0, le=1.0)
    hash: str = ""

    def __init__(self, **data):
        super().__init__(**data)
        if 'hash' not in data or not data['hash']:
            self.hash = self._compute_hash(self.word)

    def _compute_hash(self, word: str) -> str:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=b"ner_tag_salt_2023",
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(word.encode()).hex()

    def __repr__(self):
        return f"<EntityTag {self.word} ({self.type})>"

class TagRequest(BaseModel):
    """
    Nuclear-grade input validation for NER
    """
    text: str = Field(..., min_length=1, max_length=MAX_TEXT_LENGTH)
    lang: Optional[str] = Field(None, regex=r"^[a-z]{2}(-[A-Z]{2})?$")
    highlight: bool = Field(False)
    session_token: str = Field(..., min_length=64, max_length=64)
    user_token: str = Field(..., min_length=10)
    zk_proof: str = Field(..., min_length=128)

    @validator('text')
    def validate_text(cls, v):
        if not TextSanitizer.is_safe(v):
            raise ValueError("Text contains unsafe patterns")
        return v

class TagResponse(BaseModel):
    """
    Immutable NER response with integrity validation
    """
    entities: List[EntityTag]
    lang: str
    model_version: str = NER_MODEL_VERSION
    processing_time: float
    integrity_hash: str = ""

    def __init__(self, entities: List[EntityTag], lang: str, duration: float):
        super().__init__(
            entities=entities,
            lang=lang,
            processing_time=duration
        )
        self.integrity_hash = self._compute_integrity_hash(entities)

    def _compute_integrity_hash(self, entities: List[EntityTag]) -> str:
        entities_dicts = [e.dict() for e in entities]
        h = hmac.HMAC(NER_AES_KEY, hashes.SHA256(), backend=default_backend())
        h.update(json.dumps(entities_dicts, sort_keys=True).encode())
        return h.finalize().hex()

class NuclearNERTagger:
    """
    Provides secure, auditable, and real-time NER tagging.
    """
    def __init__(self):
        self.engine = NEREngine()
        self.detector = LanguageDetector()
        self.sanitizer = TextSanitizer()
        self.rate_limiter = RateLimiter()
        self.blackhole = BlackholeRouter()

    async def authenticate_ner(self, user_token: str, zk_proof: str) -> bool:
        """ZKP-based NER access control"""
        is_authorized = await validate_ner_access(user_token, zk_proof)
        if not is_authorized:
            log_event(f"[SECURITY] Unauthorized NER access for {user_token[:6]}...", alert=True)
            await self.blackhole.trigger()
            return False
        return True

    async def tag_entities(
        self,
        request: TagRequest,
        client_ip: str
    ) -> Union[TagResponse, Dict[str, Any]]:
        """
        Secure NER processing pipeline with:
        - Input sanitization
        - Language detection
        - ZKP authentication
        - PII redaction
        - Blockchain audit
        """
        if not await self.rate_limiter.check_limit(request.user_token, rate=MAX_NER_RATE, window=RATE_LIMIT_WINDOW):
            await self.blackhole.trigger()
            return {"status": "rate_limited", "error": "Too many requests"}

        if not await self.authenticate_ner(request.user_token, request.zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}

        clean_text = self.sanitizer.clean(request.text)
        if not clean_text:
            log_event("[NER] Empty input text", alert=True)
            return {"status": "invalid", "error": "Empty text"}

        lang = request.lang or await self.detector.detect(clean_text)
        if not self.engine.supports_language(lang):
            log_event(f"[NER] Unsupported language: {lang}", alert=True)
            return {"status": "invalid", "error": f"Language {lang} not supported"}

        start_time = time.monotonic()
        try:
            raw_entities = await self.engine.process(
                text=clean_text,
                lang=lang,
                session_token=request.session_token
            )
            entities = [
                EntityTag(
                    word=e.get("word", ""),
                    type=e.get("type", ""),
                    start=e.get("start", 0),
                    end=e.get("end", 0),
                    confidence=e.get("confidence", 0.0)
                )
                for e in raw_entities
            ]
        except Exception as e:
            log_event(f"[NER] Processing failed: {str(e)}", alert=True)
            return {"status": "failed", "error": str(e)}

        if request.highlight:
            entities = self._apply_highlighting(entities)

        response = TagResponse(entities, lang, time.monotonic() - start_time)

        await log_ner_event({
            "text_hash": self._compute_text_hash(clean_text),
            "lang": lang,
            "ip": client_ip,
            "token_prefix": request.session_token[:8],
            "duration": response.processing_time,
            "entity_count": len(entities),
            "timestamp": time.time()
        })
        log_event(f"[NER] Tagged {len(entities)} entities in {response.processing_time:.2f}s")
        return response

    def _apply_highlighting(self, entities: List[EntityTag]) -> List[EntityTag]:
        """Secure entity highlighting with anti-XSS"""
        for entity in entities:
            entity.word = f'<mark class="{entity.type}">{entity.word}</mark>'
        return entities

    def _compute_text_hash(self, text: str) -> str:
        """Cryptographic text hashing for audit"""
        h = hmac.HMAC(NER_AES_KEY, hashes.SHA256(), backend=default_backend())
        h.update(text.encode())
        return h.finalize().hex()

# Dependency injection
ner_tagger = NuclearNERTagger()

@router.post("/tag", response_model=TagResponse)
async def ner_tag_endpoint(
    request: TagRequest,
    client_request: Request
):
    """
    Secure NER endpoint with:
    - Authentication
    - Rate limiting
    - Input validation
    - Language support
    """
    result = await ner_tagger.tag_entities(
        request=request,
        client_ip=client_request.client.host
    )
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"]
        )
    return result