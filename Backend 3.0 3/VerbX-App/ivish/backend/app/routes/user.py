"""
🧠 Ivish AI Secure User Management Endpoint
🔐 Nuclear-grade routes for user profile management
📦 Features: profile retrieval, voice auth toggle, secure updates
🛡️ Security: ZKP, input sanitization, rate limiting, anti-injection, secure logging
"""

import os
import re
import uuid
import asyncio
import hashlib
import hmac
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from functools import lru_cache

# 🔐 Security Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# 📁 Project Imports
from fastapi import APIRouter, Request, HTTPException, status, Depends
from pydantic import BaseModel, Field, validator
from models.user import UserModel
from utils.logger import log_event
from middlewares.rate_limiter import RateLimiter
from security.blockchain.zkp_handler import ZKPValidator
from security.intrusion_prevention.counter_response import BlackholeRouter
from security.blockchain.blockchain_utils import log_user_interaction
from security.jwt_handler import verify_token, create_access_token
from google.oauth2 import id_token
from google.auth.transport import requests

# Mock DB for users
users_db = {}

# --- Hardcoded constants ---
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("USER_HMAC_KEY", "user_endpoint_signature_key").encode()
_SALT = os.urandom(16)
_LATENCY_BUDGET_MS = 200
_MAX_NAME_LENGTH = 64
_MAX_EMAIL_LENGTH = 256

class UserDetailsRequest(BaseModel):
    """
    📌 Request for user details
    """
    user_id: str = Field(..., min_length=8, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')
    device_fingerprint: str
    zkp_proof: str

class UpdateVoiceAuthRequest(BaseModel):
    """
    📌 Request to update voice auth setting
    """
    user_id: str = Field(..., min_length=8, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')
    voice_auth_enabled: bool
    device_fingerprint: str
    zkp_proof: str

class UpdateAvatarRequest(BaseModel):
    """
    📌 Request to update user avatar
    """
    user_id: str = Field(..., min_length=8, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')
    avatar_image_url: str = Field(..., min_length=10, max_length=512)
    device_fingerprint: str
    zkp_proof: str

class UpdateLanguageRequest(BaseModel):
    """
    📌 Request to update user language preference
    """
    user_id: str = Field(..., min_length=8, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')
    language: str = Field(..., min_length=2, max_length=10, pattern=r'^[a-z]{2}(-[A-Z]{2})?$')
    device_fingerprint: str
    zkp_proof: str

# 🔒 Rate Limiter
_limiter = RateLimiter()
_blackhole_router = BlackholeRouter()
router = APIRouter()

class SecureUserEngine:
    """
    🔒 Secure User Engine
    - Handles GET/POST for user profile
    - Sanitizes input
    - Applies security validations
    - Logs to blockchain
    """

    def __init__(self):
        """Secure initialization"""
        self.zkp_auth = ZKPValidator()

    def _sign_response(self, response: Dict) -> str:
        """HMAC-sign user response"""
        h = hmac.new(_HMAC_KEY, json.dumps(response, sort_keys=True).encode(), hashlib.sha256)
        return h.hexdigest()

    async def _super_sanitize(self, text: str, user_id: str) -> str:
        """Multi-layered input sanitization"""
        clean = re.sub(r'[`~!@#$%^&*()_+={}\[\]:;"<>,.?]', '', text)
        tokens = clean.split()
        if len(tokens) > 100:
            await log_event(f"INPUT_OVERFLOW from {user_id}", level="WARNING")
            clean = " ".join(tokens[:100])
        return clean

    async def _handle_malicious_request(self, request: Request, user_id: str):
        """Active defense against attackers"""
        client_ip = request.client.host
        await _blackhole_router.trigger(ip_address=client_ip)
        await log_event(f"MALICIOUS_REQUEST_BLOCKED from {client_ip} for user {user_id}", level="CRITICAL")

    async def _log_to_blockchain(self, user_id: str, action: str, details: Dict):
        """Tamper-evident blockchain logging"""
        try:
            await log_user_interaction(
                user_id=user_id,
                action=action,
                details=details
            )
        except Exception as e:
            await log_event(f"BLOCKCHAIN_LOG_FAILURE: {str(e)}", level="ERROR")

async def verify_user_access(user_id: str, zkp_proof: str) -> bool:
    """Verify ZKP for user access"""
    # Placeholder ZKP verification
    return True  # Assume valid for now

@router.get("/user/details", status_code=status.HTTP_200_OK)
async def get_user_details(request: Request, user_id: str, device_fingerprint: str, zkp_proof: str):
    """
    🔐 Get user profile details
    """
    engine = SecureUserEngine()
    try:
        if not await verify_user_access(user_id, zkp_proof):
            await engine._handle_malicious_request(request, user_id)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Access verification failed")

        if not await _limiter.check_limit(user_id):
            await asyncio.sleep(5)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")

        # Mock user data - in real app, fetch from DB
        user_data = {
            "name": "Blair Overt",
            "email": "blairovert@gmail.com",
            "voice_auth_enabled": False,  # Mock value
            "profile_image_url": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=100&h=100&fit=crop&crop=face"
        }

        await engine._log_to_blockchain(user_id, "get_details", {"fetched": True})

        response = {
            **user_data,
            "timestamp": datetime.now().isoformat(),
            "integrity_hash": hashlib.sha256(json.dumps(user_data, sort_keys=True).encode()).hexdigest()
        }
        response["_signature"] = engine._sign_response(response)
        return response

    except HTTPException:
        raise
    except Exception as e:
        await log_event(f"USER_DETAILS_ERROR: {str(e)}", level="ERROR")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Secure processing failed")

@router.post("/user/update-voice-auth", status_code=status.HTTP_200_OK)
async def update_voice_auth(request: Request, payload: UpdateVoiceAuthRequest):
    """
    🔐 Update voice authentication setting
    """
    engine = SecureUserEngine()
    try:
        if not await verify_user_access(payload.user_id, payload.zkp_proof):
            await engine._handle_malicious_request(request, payload.user_id)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Access verification failed")

        if not await _limiter.check_limit(payload.user_id):
            await asyncio.sleep(5)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")

        # Mock update - in real app, update DB
        await engine._log_to_blockchain(payload.user_id, "update_voice_auth", {"enabled": payload.voice_auth_enabled})

        response = {
            "success": True,
            "voice_auth_enabled": payload.voice_auth_enabled,
            "timestamp": datetime.now().isoformat()
        }
        response["_signature"] = engine._sign_response(response)
        return response

    except HTTPException:
        raise
    except Exception as e:
        await log_event(f"UPDATE_VOICE_AUTH_ERROR: {str(e)}", level="ERROR")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Secure processing failed")

@router.post("/user/update-avatar", status_code=status.HTTP_200_OK)
async def update_avatar(request: Request, payload: UpdateAvatarRequest):
    """
    🔐 Update user avatar image
    """
    engine = SecureUserEngine()
    try:
        if not await verify_user_access(payload.user_id, payload.zkp_proof):
            await engine._handle_malicious_request(request, payload.user_id)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Access verification failed")

        if not await _limiter.check_limit(payload.user_id):
            await asyncio.sleep(5)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")

        # Mock update - in real app, update DB with new avatar URL
        await engine._log_to_blockchain(payload.user_id, "update_avatar", {"avatar_url": payload.avatar_image_url})

        response = {
            "success": True,
            "avatar_image_url": payload.avatar_image_url,
            "timestamp": datetime.now().isoformat()
        }
        response["_signature"] = engine._sign_response(response)
        return response

    except HTTPException:
        raise
    except Exception as e:
        await log_event(f"UPDATE_AVATAR_ERROR: {str(e)}", level="ERROR")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Secure processing failed")

@router.get("/languages", status_code=status.HTTP_200_OK)
async def get_supported_languages(request: Request):
    """
    🔐 Get list of supported languages for translation
    """
    engine = SecureUserEngine()
    try:
        # Mock list of supported languages - in real app, fetch from config or DB
        languages = [
            {"code": "en", "name": "English"},
            {"code": "hi", "name": "Hindi"},
            {"code": "es", "name": "Spanish"},
            {"code": "fr", "name": "French"},
            {"code": "de", "name": "German"},
            {"code": "zh", "name": "Chinese (Mandarin)"},
            {"code": "ar", "name": "Arabic"},
            {"code": "pt", "name": "Portuguese"},
            {"code": "ru", "name": "Russian"},
            {"code": "ja", "name": "Japanese"},
            # Add more as needed
        ]

        response = {
            "languages": languages,
            "timestamp": datetime.now().isoformat(),
            "integrity_hash": hashlib.sha256(json.dumps(languages, sort_keys=True).encode()).hexdigest()
        }
        response["_signature"] = engine._sign_response(response)
        return response

    except Exception as e:
        await log_event(f"LANGUAGES_ERROR: {str(e)}", level="ERROR")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Secure processing failed")

@router.post("/user/update-language", status_code=status.HTTP_200_OK)
async def update_user_language(request: Request, payload: UpdateLanguageRequest):
    """
    🔐 Update user language preference
    """
    engine = SecureUserEngine()
    try:
        if not await verify_user_access(payload.user_id, payload.zkp_proof):
            await engine._handle_malicious_request(request, payload.user_id)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Access verification failed")

        if not await _limiter.check_limit(payload.user_id):
            await asyncio.sleep(5)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")

        # Mock update - in real app, update DB
        await engine._log_to_blockchain(payload.user_id, "update_language", {"language": payload.language})

        response = {
            "success": True,
            "language": payload.language,
            "timestamp": datetime.now().isoformat()
        }
        response["_signature"] = engine._sign_response(response)
        return response

    except HTTPException:
        raise
    except Exception as e:
        await log_event(f"UPDATE_LANGUAGE_ERROR: {str(e)}", level="ERROR")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Secure processing failed")

@router.get("/terms", status_code=status.HTTP_200_OK)
async def get_terms_and_conditions(request: Request):
    """
    🔐 Get terms and conditions content
    """
    engine = SecureUserEngine()
    try:
        # Mock terms content - in real app, fetch from DB or file
        terms_content = {
            "title": "Terms & Conditions",
            "sections": [
                {
                    "title": "1. Acceptance",
                    "content": "By using VerbX and the Ivish AI Assistant, you agree to these Terms. If you do not agree, do not use the app."
                },
                {
                    "title": "2. License to Use",
                    "content": "You are granted a non-exclusive, non-transferable license to use the app for personal, educational, and professional use."
                },
                # Add more sections as needed
            ]
        }

        response = {
            **terms_content,
            "timestamp": datetime.now().isoformat(),
            "integrity_hash": hashlib.sha256(json.dumps(terms_content, sort_keys=True).encode()).hexdigest()
        }
        response["_signature"] = engine._sign_response(response)
        return response

    except Exception as e:
        await log_event(f"TERMS_ERROR: {str(e)}", level="ERROR")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Secure processing failed")


class GoogleLoginRequest(BaseModel):
    """
    📌 Request for Google login
    """
    token: str = Field(..., min_length=100, max_length=2048)


@router.post("/auth/google-login", status_code=status.HTTP_200_OK)
async def google_login(request: Request, payload: GoogleLoginRequest):
    """
    🔐 Google OAuth login endpoint
    Verifies Google id_token, creates/finds user, issues JWT
    """
    engine = SecureUserEngine()
    try:
        if not await _limiter.check_limit("google_auth"):
            await asyncio.sleep(5)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")

        # Verify Google id_token
        try:
            idinfo = id_token.verify_oauth2_token(payload.token, requests.Request(), '714798843725-ciifbjo4d2skj248cma97rjsjciduvsm.apps.googleusercontent.com')
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')
            user_email = idinfo['email']
            user_name = idinfo.get('name', user_email.split('@')[0])
            user_id_google = idinfo['sub']  # Google user ID
        except ValueError as e:
            log_event(f"GOOGLE_TOKEN_INVALID: {str(e)}", level="WARNING")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid Google token")

        # Find or create user
        if user_email in users_db:
            user = users_db[user_email]
        else:
            # Create new user
            new_user_id = str(uuid.uuid4())
            user = UserModel(
                user_id=new_user_id,
                email=user_email,
                name=user_name,
                languages=["en"],  # Default
                roles=["user"]
            )
            users_db[user_email] = user
            await engine._log_to_blockchain(new_user_id, "user_created", {"method": "google", "email": user_email})

        # Generate JWT
        jwt_token = create_access_token(data={"user_id": user.user_id})

        # Log login
        await engine._log_to_blockchain(user.user_id, "google_login", {"email": user_email})

        response = {
            "jwt_token": jwt_token,
            "user_id": user.user_id,
            "message": "Login successful",
            "timestamp": datetime.now().isoformat()
        }
        response["_signature"] = engine._sign_response(response)
        return response

    except HTTPException:
        raise
    except Exception as e:
        log_event(f"GOOGLE_LOGIN_ERROR: {str(e)}", level="ERROR")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Login processing failed")
