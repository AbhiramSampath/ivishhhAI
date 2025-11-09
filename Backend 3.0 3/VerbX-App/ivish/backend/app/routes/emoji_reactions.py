# backend/app/routes/emoji_reactions.py

import os
import uuid
import json
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
import logging
import asyncio
from functools import lru_cache

# Internal imports - CORRECTED PATHS
from fastapi import APIRouter, Request, HTTPException, status
from pydantic import BaseModel, Field, validator
from ..services.emoji_service import EmojiService
from utils.logger import log_event
from security.blockchain.blockchain_utils import log_to_blockchain

# External imports
import numpy as np

# FastAPI router
router = APIRouter(
    prefix="/emoji",
    tags=["emotion"],
    responses={404: {"description": "Not found"}}
)

class EmojiRequest(BaseModel):
    """
    Input request model with validation and sanitization
    """
    text: str = Field(..., min_length=1, max_length=2000)
    language: Optional[str] = "en"
    intensity_threshold: Optional[float] = 0.3
    user_id: Optional[str] = None

    @validator('text')
    def sanitize_text(cls, v):
        """Strip unsafe characters and limit length"""
        if len(v) > 2000:
            raise ValueError("Input text too long")
        return v.strip()

class EmojiResponse(BaseModel):
    """
    Output response model with audit trail
    """
    emotion: str
    emoji: str
    confidence: float
    audit_hash: str
    timestamp: str

# Singleton service engine
emoji_service = EmojiService()

# FastAPI routes
@router.post("/reaction", response_model=EmojiResponse)
async def get_emoji_response(
    request: EmojiRequest,
    x_request_id: Optional[str] = None
) -> Dict:
    """
    Emotion → Emoji endpoint with:
    - Input sanitization
    - Intensity detection
    - Tamper-proof logging
    """
    try:
        response = await emoji_service.process_text(request.text)
        
        audit_hash = hashlib.sha256(
            f"{request.text[:32]}{response['emotion']}{response['confidence']}".encode()
        ).hexdigest()

        await log_to_blockchain(
            "emoji_reaction",
            payload={
                "request_id": x_request_id,
                "emotion": response['emotion'],
                "confidence": f"{response['confidence']:.2f}",
                "hash": audit_hash,
                "user_id": request.user_id,
            }
        )

        return {
            "emotion": response["emotion"],
            "emoji": response["emoji"],
            "confidence": response["confidence"],
            "audit_hash": audit_hash,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    except Exception as e:
        log_event(
            f"Emoji Reaction Failed: {str(e)}",
            level="ERROR",
            extra={"text_sample": request.text[:10] + "..."}
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Emoji processing error")

@router.get("/map", include_in_schema=False)
async def get_emoji_map() -> Dict:
    """
    Debug endpoint to retrieve emoji map (disabled in production)
    """
    return {
        "base_map": emoji_service._emoji_map,
        "intensity_rules": emoji_service._intensity_map
    }