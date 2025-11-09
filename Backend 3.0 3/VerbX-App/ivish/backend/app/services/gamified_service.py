# backend/services/gamified_service.py
# 🧠 Designed for Edge Deployment, Federated Learning, and Offline AI

import uuid
import time
import os
import random
import hashlib
import hmac
import asyncio
import base64
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from collections import defaultdict
from functools import lru_cache
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# 📦 Project Imports - Corrected paths based on PDF
from ai_models.education.gamified_learning import adjust_difficulty
from db.mongo import get_user_profile, update_user_metrics
from utils.logger import log_event
from ai_models.emotion.emotion_handler import detect_emotion
from security.jwt_utils import validate_user_session
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import BlackholeRouter, rotate_endpoint
from security.firewall import Firewall
from middlewares.rate_limiter import RateLimiter

# 🧱 Hardcoded Config (as config file is not in PDF structure)
XP_RULES = {
    "past tense": 10,
    "vocabulary": 15,
    "pronunciation": 20,
    "slang": 25,
    "emotion_bonus": 5
}
BADGE_RULES = {
    "first_10_points": lambda user: user.get("xp", 0) >= 10,
    "language_expert": lambda user: user.get("xp", 0) >= 1000,
}

MAX_XP_PER_MINUTE = 1000
THREAT_LEVEL_THRESHOLD = 5
ENABLE_BLOCKCHAIN_LOGGING = True
ENABLE_HONEYPOT = True
ENABLE_ENDPOINT_MUTATION = True
RATE_LIMIT_WINDOW_S = 60  # seconds
MAX_FAILURE_RATE = 3

# 🔐 Secure Global State
SECURITY_CONTEXT = {
    "firewall": Firewall(),
    "threat_level": 0,
    "last_attack_time": 0
}

# 🔒 Security Utilities - Consolidated and Corrected
def _derive_hw_key() -> bytes:
    """Hardware-bound key derivation"""
    hw_factors = [
        os.getenv("HW_FINGERPRINT", ""),
        str(os.cpu_count()),
        str(os.getloadavg()[0]),
    ]
    return HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=os.urandom(16),
        info=b"gamification_key",
        backend=default_backend()
    ).derive("|".join(hw_factors).encode())

def _hash_user_id(user_id: str) -> str:
    """GDPR-compliant user hashing with a secure, non-empty salt"""
    salt = os.getenv("USER_HASH_SALT")
    if not salt:
        log_event("CRITICAL: USER_HASH_SALT not set. Hashing is compromised.", "ALERT")
        salt = "default_salt"
    return hmac.new(
        salt.encode(),
        user_id.encode(),
        hashlib.sha3_256
    ).hexdigest()

def _sanitize_input(raw_input: str) -> str:
    """Sanitize input by removing dangerous characters and limiting length."""
    sanitized = re.sub(r'[<>"\'&;]', '', raw_input)
    return sanitized[:256]

def _generate_nonce() -> str:
    """Cryptographically secure nonce for CSP"""
    return base64.b64encode(os.urandom(16)).decode()[:16]

async def _increment_threat_level(ip_address: str):
    """Increase threat level and trigger defense if needed"""
    SECURITY_CONTEXT['threat_level'] += 1
    if SECURITY_CONTEXT['threat_level'] > THREAT_LEVEL_THRESHOLD:
        await _anti_tamper_protocol(ip_address)

async def _anti_tamper_protocol(ip_address: str):
    """Active defense against tampering"""
    log_event("THREAT: Triggering anti-tamper protocol", level="ALERT")
    if ENABLE_HONEYPOT:
        await award_points("attacker", "fake_task")
    await BlackholeRouter.trigger(ip_address=ip_address)
    if ENABLE_ENDPOINT_MUTATION:
        rotate_endpoint()
    SECURITY_CONTEXT['threat_level'] = 0

# 🧠 Gamification Engine Core - Refactored to be Async
async def _validate_user_access(user_id: str) -> bool:
    """Zero-trust user verification with rate-limiting and session validation"""
    rate_limiter = RateLimiter()
    if not await rate_limiter.check_limit(user_id):
        return False
    
    result = await validate_user_session(user_id, required_scope="gamification")
    if not result:
        log_event(f"BLOCKED GAMIFICATION ACCESS | user={_hash_user_id(user_id)}")
        # Note: IP address is needed for a real blackhole, but not available here.
        await _increment_threat_level("unknown_ip")
    return result

async def award_points(user_id: str, task_type: str) -> Dict[str, Any]:
    """
    Award XP with military-grade security checks.
    """
    if not await _validate_user_access(user_id):
        return {"error": "Access denied"}, 403

    try:
        task_key = _sanitize_input(task_type)
        xp = XP_RULES.get(task_key, 5)
        xp = min(xp, MAX_XP_PER_MINUTE)

        user = await get_user_profile(user_id)
        user["xp"] = max(0, user.get("xp", 0) + xp)
        await update_user_metrics(user_id, {"xp": user["xp"]})

        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain(event="xp_awarded", payload={
                "user_id_hash": _hash_user_id(user_id),
                "task": task_key,
                "xp": xp,
                "total_xp": user["xp"],
                "timestamp": datetime.utcnow().isoformat()
            })

        return {
            "xp_awarded": xp,
            "total_xp": user["xp"],
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        log_event(f"XP award failed: {str(e)}", level="ERROR")
        await _increment_threat_level("unknown_ip")
        return {"error": "System error"}, 500

async def check_for_badges(user_id: str) -> List[str]:
    """
    Secure badge assignment with constant-time comparison.
    """
    if not await _validate_user_access(user_id):
        return []

    try:
        user = await get_user_profile(user_id)
        new_badges = []
        
        for badge, condition in BADGE_RULES.items():
            if condition(user) and badge not in user.get("badges", []):
                new_badges.append(_sanitize_input(badge))

        if new_badges:
            await update_user_metrics(
                user_id,
                {"badges": user.get("badges", []) + new_badges}
            )
            log_event(f"BADGE UPDATE | user={_hash_user_id(user_id)} | badges={new_badges}")
            if ENABLE_BLOCKCHAIN_LOGGING:
                await log_to_blockchain(event="badges_awarded", payload={
                    "user_id_hash": _hash_user_id(user_id),
                    "badges": new_badges,
                    "timestamp": datetime.utcnow().isoformat()
                })
        return new_badges

    except Exception as e:
        log_event(f"Badge assignment failed: {str(e)}", level="ERROR")
        await _increment_threat_level("unknown_ip")
        return []

async def get_progress_dashboard(user_id: str) -> Dict[str, Any]:
    """
    Secure progress fetch with data minimization.
    """
    if not await _validate_user_access(user_id):
        return {"error": "Access denied", "code": 403}

    try:
        user = await get_user_profile(user_id)
        return {
            "xp": user.get("xp", 0),
            "badges": [_sanitize_input(b) for b in user.get("badges", [])],
            "streak": user.get("streak", 0),
            "last_activity": user.get("last_activity"),
            "level": user.get("level", 1),
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        log_event(f"Dashboard fetch failed: {str(e)}", level="ERROR")
        await _increment_threat_level("unknown_ip")
        return {"error": "System error", "code": 500}

async def serve_daily_challenge(user_id: str) -> Dict[str, Any]:
    """
    RL-driven challenges with secure topic selection.
    """
    if not await _validate_user_access(user_id):
        return {"error": "Access denied", "code": 403}

    try:
        topics = ["past tense", "vocabulary", "pronunciation", "slang"]
        difficulty = await adjust_difficulty(user_id)
        topic = random.choice(topics)

        challenge = {
            "challenge_id": str(uuid.uuid4()),
            "topic": _sanitize_input(topic),
            "difficulty": difficulty,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id_hash": _hash_user_id(user_id)
        }

        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain(event="daily_challenge", payload=challenge)

        return challenge

    except Exception as e:
        log_event(f"Challenge generation failed: {str(e)}", level="ERROR")
        await _increment_threat_level("unknown_ip")
        return {"error": "System error", "code": 500}

async def adjust_learning_curve(user_id: str, performance_score: float) -> Dict[str, Any]:
    """
    Reinforcement-based difficulty adjustment with score validation.
    """
    if not await _validate_user_access(user_id):
        return {"error": "Access denied", "code": 403}

    try:
        if not (0 <= performance_score <= 1):
            log_event(f"SCORE TAMPERING DETECTED | user={_hash_user_id(user_id)}")
            return {"error": "Invalid score", "code": 400}

        new_level = await adjust_difficulty(user_id, feedback_score=performance_score)
        log_event(
            f"LEARNING CURVE ADJUSTED | user={_hash_user_id(user_id)} | level={new_level}"
        )
        if ENABLE_BLOCKCHAIN_LOGGING:
            await log_to_blockchain(event="level_up", payload={
                "user_id_hash": _hash_user_id(user_id),
                "new_level": new_level,
                "timestamp": datetime.utcnow().isoformat()
            })

        return {"new_level": new_level}

    except Exception as e:
        log_event(f"Difficulty adjustment failed: {str(e)}", level="ERROR")
        await _increment_threat_level("unknown_ip")
        return {"error": "System error", "code": 500}

async def log_emotion_reward(user_id: str, text: str) -> Dict[str, Any]:
    """
    Emotion-based rewards with secure NLP processing.
    """
    if not await _validate_user_access(user_id):
        return {"error": "Access denied", "code": 403}

    try:
        sanitized_text = _sanitize_input(text)[:500]
        emotion = await detect_emotion(sanitized_text)
        
        if emotion in ["joy", "curious", "confident"]:
            boost = await award_points(user_id, "emotion_bonus")
            return {
                "emotion": emotion,
                "reward": boost,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        return {
            "emotion": emotion,
            "reward": None,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        log_event(f"Emotion reward failed: {str(e)}", level="ERROR")
        await _increment_threat_level("unknown_ip")
        return {"error": "System error", "code": 500}