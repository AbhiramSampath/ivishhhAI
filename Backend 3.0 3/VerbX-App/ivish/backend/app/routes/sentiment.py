import os
import asyncio
import json
import hashlib
import hmac
import re
from typing import Optional, Dict, Any, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
import uuid
from fastapi import APIRouter, Request, Response, status, HTTPException, Depends
from pydantic import BaseModel, Field, validator
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Security: Corrected imports
from security.firewall import Firewall as NuclearSanitizer
from middlewares.rate_limiter import RateLimiter as AnalysisRateLimiter
from utils.logger import log_event, security_alert as log_audit_event
from security.intrusion_prevention.counter_response import BlackholeRouter
from ..auth.jwt_handler import SignResponse
from ai_models.emotion.emotion_handler import detect_emotion
from ai_models.sentiment.sentiment_analyzer import classify_sentiment
from ai_models.model_monitor import check_model_status

# --- Hardcoded Constants (from non-existent config file) ---
EMOTION_LOGGING_ENABLED = os.getenv("EMOTION_LOGGING_ENABLED", "True").lower() == "true"
SENTIMENT_MODEL_VERSION = os.getenv("SENTIMENT_MODEL_VERSION", "v1.0")
_SENTIMENT_HASH_SECRET = os.getenv("SENTIMENT_HASH_SECRET", os.urandom(32)).encode()
_MAX_TEXT_LENGTH = 1000

# --- Initialize secure components ---
router = APIRouter()
sanitizer = NuclearSanitizer()
rate_limiter = AnalysisRateLimiter(requests=100, window=60)
response_signer = SignResponse()
blackhole_router = BlackholeRouter()

class SentimentEnum(str, Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"
    MIXED = "mixed"

class EmotionEnum(str, Enum):
    HAPPY = "happy"
    SAD = "sad"
    ANGRY = "angry"
    SURPRISED = "surprised"
    FEARFUL = "fearful"
    DISGUST = "disgust"
    NEUTRAL = "neutral"

class SentimentRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=1000)
    user_id: Optional[str] = Field(
        None,
        regex=r"^usr_[a-zA-Z0-9]{20}$",
        description="Strictly formatted user reference"
    )
    lang: str = Field(
        "en-US",
        regex=r"^[a-z]{2,3}(-[A-Z]{2,3})?$",
        description="BCP-47 language tag"
    )
    request_id: str = Field(
        default_factory=lambda: f"req_{uuid.uuid4().hex}",
        description="Traceable request ID"
    )

    @validator('text')
    def validate_text(cls, v):
        if not v or len(v) > _MAX_TEXT_LENGTH:
            raise ValueError("Input too long or empty")
        if sanitizer.is_malicious(v):
            log_event("malicious_input_blocked", input_hash=hashlib.blake2s(v.encode()).hexdigest())
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Malicious input detected"
            )
        return v

    @validator('lang')
    def validate_language(cls, v):
        if not v or not re.match(r"^[a-z]{2,3}(-[A-Z]{2,3})?$", v):
            raise ValueError(f"Unsupported language: {v}")
        return v

    @validator('user_id')
    def validate_user_id(cls, v):
        if v and not re.match(r"^usr_[a-zA-Z0-9]{20}$", v):
            raise ValueError(f"Invalid user ID: {v}")
        return v

class SentimentResponse(BaseModel):
    sentiment: SentimentEnum
    emotion: EmotionEnum
    confidence: float = Field(..., ge=0.0, le=1.0)
    sanitized_input: str
    language: str
    model_version: str
    analyzed_at: str
    integrity_hash: str

def _generate_integrity_hash(input_text: str, timestamp: datetime) -> str:
    h = hmac.HMAC(_SENTIMENT_HASH_SECRET, hashes.SHA3_256(), backend=default_backend())
    h.update(f"{input_text}{timestamp.isoformat()}".encode())
    return h.finalize().hex()

@router.post(
    "/analyze/sentiment",
    response_model=SentimentResponse,
    summary="Secure Sentiment Analysis",
    description="Performs nuclear-grade sentiment and emotion detection with tamper-proof auditing",
    status_code=status.HTTP_200_OK
)
async def analyze_sentiment(
    request: SentimentRequest,
    response: Response,
    http_request: Request
):
    client_ip = http_request.client.host
    if not await rate_limiter.check_limit(f"{client_ip}|{request.user_id}"):
        log_event("rate_limit_exceeded", user_id=request.user_id, ip=client_ip)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="rate_limit_exceeded")

    try:
        sanitized = request.text
        
        with asyncio.timeout(0.5):
            sentiment_result = await classify_sentiment(sanitized, lang=request.lang)
            emotion_result = await detect_emotion(sanitized, lang=request.lang)

        if not all([sentiment_result.valid, emotion_result.valid]):
            log_event("model_output_tampering", request_id=request.request_id)
            await blackhole_router.trigger()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Model output tampering detected"
            )

        analysis_time = datetime.utcnow().replace(microsecond=0)
        response_data = {
            "sentiment": sentiment_result.label,
            "emotion": emotion_result.label,
            "confidence": min(sentiment_result.confidence, emotion_result.confidence),
            "sanitized_input": sanitized,
            "language": request.lang,
            "model_version": SENTIMENT_MODEL_VERSION,
            "analyzed_at": analysis_time.isoformat() + "Z",
            "integrity_hash": _generate_integrity_hash(sanitized, analysis_time)
        }

        if EMOTION_LOGGING_ENABLED and request.user_id:
            await log_event(
                "sentiment_analysis",
                user_id=request.user_id,
                sentiment=sentiment_result.label,
                emotion=emotion_result.label,
                input_hash=hashlib.blake2s(sanitized.encode()).hexdigest(),
                request_id=request.request_id
            )

        signed_response = response_signer.sign(response_data)
        response.headers["X-Integrity"] = signed_response["signature"]
        
        return signed_response["data"]

    except asyncio.TimeoutError:
        log_event("analysis_timeout", request_id=request.request_id)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"error": "analysis_timeout"}
    except Exception as e:
        log_event("analysis_failed", error=str(e), request_id=request.request_id)
        await blackhole_router.trigger()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Nuclear-grade analysis failed"
        )

@router.get("/analyze/sentiment/test")
async def test_sentiment():
    try:
        await check_model_status()
        return {
            "status": "operational",
            "model_version": SENTIMENT_MODEL_VERSION,
            "integrity_hash": hashlib.blake2s(
                SENTIMENT_MODEL_VERSION.encode(),
                key=os.getenv('SENTIMENT_HASH_SECRET', b"fallback_secret").encode(),
                digest_size=16
            ).hexdigest()
        }
    except Exception as e:
        log_event("sentiment_test_failed", error=str(e))
        return {"status": "critical"}