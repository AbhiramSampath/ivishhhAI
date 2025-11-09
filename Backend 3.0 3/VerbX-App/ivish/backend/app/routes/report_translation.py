# backend/app/routes/report_translation.py
# 🔒 Nuclear-grade document translation for PDF, DOCX, TXT, etc.

import json
import os
import re
import uuid
import asyncio
import aiofiles
import hashlib
import hmac
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, validator
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# 📁 Project Imports - CORRECTED PATHS
from backend.app.services.report_service import process_report_translation
from security.blockchain.zkp_handler import verify_document_access
from security.blockchain.blockchain_utils import log_translation_audit
from utils.helpers import sanitize_filename
from utils.logger import log_event
from middlewares.rate_limiter import RateLimiter
from security.intrusion_prevention.counter_response import BlackholeRouter

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("REPORT_TRANSLATION_HMAC_KEY", os.urandom(32)).encode()
_SALT = os.urandom(16)
_KDF_ITERATIONS = 100000
_LATENCY_BUDGET_MS = 5000
_SUPPORTED_FORMATS = ('.pdf', '.docx', '.txt', '.rtf', '.pptx', '.xlsx')
_SUPPORTED_LANGS = ['en', 'hi', 'ta', 'te', 'bn', 'kn', 'es', 'fr', 'de', 'ru', 'ja', 'zh']
_MAX_FILE_SIZE = 10 * 1024 * 1024
_SECURE_TEMP_STORAGE = os.getenv("SECURE_TEMP_STORAGE", "/secure_tmp/translation")

# 🔒 Rate Limiter
_limiter = RateLimiter(
    max_requests=10,
    period=86400,
    model_weights={"legal": 3, "medical": 5}
)

# 📦 Pydantic Model
class DocumentTranslationRequest(BaseModel):
    target_lang: str = Field(..., min_length=2, max_length=5)
    tone: str = Field("formal", regex=r'^(formal|polite|neutral|friendly)$')
    user_id: str = Field(..., min_length=8, max_length=64)
    consent_token: str
    device_fingerprint: str
    file_type: str = ""

    @validator("target_lang")
    def validate_language(cls, v):
        if v not in _SUPPORTED_LANGS:
            raise ValueError("Unsupported language")
        return v

    @validator("file_type")
    def validate_file_type(cls, v):
        if v not in _SUPPORTED_FORMATS:
            raise ValueError("Unsupported file type")
        return v

# 📁 FastAPI Router
router = APIRouter()
blackhole_router = BlackholeRouter()

@dataclass
class TranslationResponse:
    status: str
    translation_id: str
    document_hash: str
    download_url: str
    timestamp: str
    _signature: Optional[str] = None

class SecureReportTranslationEngine:
    def __init__(self):
        self._init_rate_limiter()
        self._init_blockchain_logger()

    def _init_rate_limiter(self):
        self.limiter = _limiter

    def _init_blockchain_logger(self):
        self.blockchain_logger = log_translation_audit

    def _sign_response(self, response: Dict) -> str:
        h = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        h.update(json.dumps(response, sort_keys=True).encode())
        return h.finalize().hex()

    async def _generate_file_hash(self, file: UploadFile) -> str:
        digest = hashes.Hash(hashes.SHA3_256(), backend=_BACKEND)
        await file.seek(0)
        while chunk := await file.read(8192):
            digest.update(chunk)
        await file.seek(0)
        return digest.finalize().hex()

    async def _handle_malicious_upload(self, file: UploadFile):
        file_hash = await self._generate_file_hash(file)
        log_event(f"MALICIOUS_DOCUMENT_UPLOAD | {file_hash}", level="CRITICAL")
        await blackhole_router.trigger()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Upload rejected")

    async def _handle_translation_failure(self, file_path: str, error: str):
        log_event(f"TRANSLATION_FAILURE: {error}")
        await self._secure_cleanup(file_path)

    async def _secure_cleanup(self, file_path: str):
        try:
            if os.path.exists(file_path):
                async with aiofiles.open(file_path, "wb") as f:
                    size = os.path.getsize(file_path)
                    await f.write(os.urandom(size))
                os.remove(file_path)
        except Exception as e:
            log_event(f"FILE_WIPE_FAILURE: {str(e)}", level="ERROR")

    @router.post("/translate/report")
    async def translate_report(
        self,
        file: UploadFile = File(...),
        target_lang: str = Form("en"),
        tone: str = Form("formal"),
        user_id: str = Form(...),
        consent_token: str = Form(...),
        device_fingerprint: str = Form(...)
    ):
        try:
            if not await verify_document_access(consent_token):
                await self._handle_malicious_upload(file)
            
            if not await self.limiter.check_limit(user_id):
                await asyncio.sleep(10)
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")

            if file.content_type not in _SUPPORTED_FORMATS:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unsupported file format")

            file_hash = await self._generate_file_hash(file)
            safe_filename = sanitize_filename(file.filename)
            temp_path = os.path.join(_SECURE_TEMP_STORAGE, f"{uuid.uuid4()}_{safe_filename}")

            if not os.path.exists(_SECURE_TEMP_STORAGE):
                os.makedirs(_SECURE_TEMP_STORAGE, exist_ok=True)

            await file.seek(0)
            async with aiofiles.open(temp_path, "wb") as f:
                while chunk := await file.read(8192):
                    await f.write(chunk)

            await log_event(f"DOCUMENT_UPLOAD | {file_hash} | User: {user_id[:6]}...", level="INFO")
            
            translation_id, translated_path = await process_report_translation(
                file_path=temp_path,
                target_lang=target_lang,
                tone=tone,
                user_id=user_id,
                encryption_key=device_fingerprint
            )

            audit_data = {
                "document_hash": file_hash,
                "user_id": user_id,
                "target_lang": target_lang,
                "translation_id": translation_id,
                "tone": tone,
                "timestamp": datetime.now().isoformat(),
                "file_type": os.path.splitext(safe_filename)[1]
            }
            await self.blockchain_logger(**audit_data)

            response = TranslationResponse(
                status="success",
                translation_id=translation_id,
                document_hash=file_hash,
                download_url=f"/download/{translation_id}/{safe_filename}",
                timestamp=datetime.now().isoformat(),
                _signature=None
            )
            response._signature = self._sign_response(response.__dict__)
            return response.__dict__

        except HTTPException:
            raise
        except Exception as e:
            await self._handle_translation_failure(temp_path, str(e))
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Secure translation failed")

    @router.get("/download/{translation_id}/{filename}")
    async def download_translation(self, translation_id: str, filename: str):
        safe_filename = sanitize_filename(filename)
        file_path = os.path.join(_SECURE_TEMP_STORAGE, f"{translation_id}_{safe_filename}")
        
        if not os.path.exists(file_path):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found or expired")

        return FileResponse(
            file_path,
            filename=safe_filename,
            headers={
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY"
            }
        )

engine = SecureReportTranslationEngine()