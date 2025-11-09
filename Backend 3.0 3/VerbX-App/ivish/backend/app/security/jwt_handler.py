"""
JWT Handler Stub
"""

import jwt
import os
from datetime import datetime, timedelta

SECRET_KEY = os.getenv("JWT_SECRET", "default_secret")
ALGORITHM = "HS256"

def get_user_id_from_token(token: str) -> str:
    """Stub function to get user ID from JWT token"""
    return "stub_user_id"

def validate_token(token: str) -> bool:
    """Stub function to validate JWT token"""
    return True

def verify_token(token: str) -> bool:
    """Stub function to verify JWT token"""
    return True

def create_access_token(data: dict) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
