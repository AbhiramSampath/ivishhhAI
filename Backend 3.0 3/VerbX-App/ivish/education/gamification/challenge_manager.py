import uuid
import random
import os
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from peewee import *

# --- Placeholder Imports for non-existent modules ---
class Challenge(Model):
    id = CharField()
    user_id = CharField()
    type = CharField()
    question = CharField()
   
    answer = CharField()
    lang = CharField()
    created_at = DateTimeField()
    expires_at = DateTimeField()
    status = CharField()
    hmac = CharField()
    score = FloatField(null=True)
    completed_at = DateTimeField(null=True)

class UserProfile(Model):
    id = CharField()
    xp = IntegerField()
    coins = IntegerField()

def generate_challenge(mode: str, lang: str) -> Dict[str, Any]:
    return {"question": "What is 1+1?", "answer": "2", "options": ["1", "2", "3"]}

def make_gpt_challenge(lang: str) -> Dict[str, Any]:
    return {"question": "What is the capital of France?", "answer": "Paris"}

def score_response(answer: str, correct_answer: str, lang: str) -> float:
    return 1.0 if answer.lower() == correct_answer.lower() else 0.0

def update_leaderboard(user_id: str, score: float):
    pass

# Corrected Imports based on project architecture
from backend.app.utils.logger import log_event, BaseLogger

# --- Security Constants ---
_HMAC_KEY = os.getenv("CHALLENGE_HMAC_KEY", os.urandom(32))
_CIPHER_SUITE = Fernet(os.getenv("CHALLENGE_FERNET_KEY", Fernet.generate_key()))
_MAX_DAILY_CHALLENGES = 20
_ANTI_CHEAT_THRESHOLD = 0.9
_CHALLENGE_TTL = timedelta(hours=24)
_BLOCKLIST: Dict[str, float] = {}
_RATE_LIMIT_WINDOW = 60
_MAX_REQUESTS_PER_MINUTE = 30
REWARD_RULES = {"xp_high": 100, "xp_med": 50, "coins_high": 10}

logger = BaseLogger(__name__)

@dataclass
class ChallengeContext:
    challenge_id: str
    user_id: str
    question: str
    correct_answer: str
    lang: str
    mode: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

def _is_rate_limited(user_id: str) -> bool:
    now = datetime.utcnow().timestamp()
    key = f"challenge:{user_id}"
    
    if key in _BLOCKLIST and now - _BLOCKLIST[key] < _RATE_LIMIT_WINDOW:
        return True
    
    _BLOCKLIST[key] = now
    return False

def _generate_secure_challenge_id(user_id: str) -> str:
    h = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(user_id.encode() + datetime.utcnow().isoformat().encode())
    return h.finalize().hex()[:32]

def _encrypt_challenge_data(data: str) -> str:
    return _CIPHER_SUITE.encrypt(data.encode()).decode()

def _decrypt_challenge_data(data: str) -> str:
    return _CIPHER_SUITE.decrypt(data.encode()).decode()

def _generate_hmac(message: str) -> bytes:
    h = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    return h.finalize()

def _verify_hmac(message: str, signature: bytes) -> bool:
    h = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    try:
        h.verify(signature)
        return True
    except:
        return False

def create_challenge(user_id: str, mode: str = "daily", language: str = "en") -> Optional[Dict]:
    if _is_rate_limited(user_id):
        log_event(f"CHALLENGE_FLOOD_ATTEMPT:{user_id}", level="WARNING")
        return None

    try:
        if mode == "gpt":
            data = make_gpt_challenge(language)
        else:
            data = generate_challenge(mode, language)
        encrypted_answer = _encrypt_challenge_data(data["answer"])
        challenge_id = _generate_secure_challenge_id(user_id)
        challenge = Challenge(
            id=challenge_id, user_id=user_id, type=mode, question=data["question"],
            options=data.get("options", []), answer=encrypted_answer, lang=language,
            created_at=datetime.utcnow(), expires_at=datetime.utcnow() + _CHALLENGE_TTL,
            status="active", hmac=_generate_hmac(data["question"]).hex()
        )
        challenge.save()
        log_event(f"CHALLENGE_CREATED:{challenge_id}:{mode}:{language}")
        return {"challenge_id": challenge_id, "question": data["question"], "type": mode, "options": data.get("options", [])}
    except Exception as e:
        log_event(f"CHALLENGE_FAILURE:{str(e)[:50]}", level="ERROR")
        return None

def submit_response(user_id: str, challenge_id: str, answer: str) -> Dict:
    try:
        challenge = Challenge.get(id=challenge_id)
        if not challenge or challenge.user_id != user_id:
            return {"status": "error", "reason": "challenge_not_found"}
        hmac_signature = bytes.fromhex(challenge.hmac)
        if not _verify_hmac(challenge.question, hmac_signature):
            log_event(f"CHALLENGE_TAMPERED:{challenge_id}", level="ALERT")
            return {"status": "error", "reason": "integrity_check_failed"}
        correct_answer = _decrypt_challenge_data(challenge.answer)
        score = score_response(answer, correct_answer, challenge.lang)
        if score >= _ANTI_CHEAT_THRESHOLD and _detect_cheating_patterns(answer, correct_answer):
            log_event(f"CHEAT_FLAGGED:{user_id}:{challenge_id}", level="WARNING")
            score = min(score, 0.7)
        challenge.status = "completed"
        challenge.score = score
        challenge.completed_at = datetime.utcnow()
        challenge.save()
        _grant_secure_rewards(user_id, score)
        update_leaderboard(user_id, score)
        return {"status": "ok", "score": round(score, 2), "xp_earned": REWARD_RULES["xp_high"] if score > 0.8 else REWARD_RULES["xp_med"]}
    except Exception as e:
        log_event(f"SUBMIT_FAILURE:{challenge_id}:{str(e)[:50]}", level="ERROR")
        return {"status": "error", "reason": "processing_error"}

def _grant_secure_rewards(user_id: str, score: float) -> None:
    try:
        with UserProfile.atomic():
            profile = UserProfile.get(id=user_id)
            rewards = {"xp": 0, "coins": 0}
            if score > 0.8:
                rewards["xp"] = REWARD_RULES["xp_high"]
                rewards["coins"] = REWARD_RULES["coins_high"]
            elif score > 0.5:
                rewards["xp"] = REWARD_RULES["xp_med"]
            profile.xp = min(profile.xp + rewards["xp"], 2**31 - 1)
            if rewards["coins"] > 0:
                profile.coins = min(profile.coins + rewards["coins"], 2**31 - 1)
            profile.save()
    except Exception as e:
        log_event(f"[ERROR] Reward granting failed: {str(e)}", level="ERROR")

def _detect_cheating_patterns(answer: str, correct_answer: str) -> bool:
    return (answer.lower() == correct_answer.lower() or len(answer.split()) < 2)

def get_daily_challenges(user_id: str) -> List[Dict]:
    try:
        today = datetime.utcnow().date()
        today_start = datetime.combine(today, datetime.min.time())
        challenges = Challenge.select().where(Challenge.user_id == user_id, Challenge.created_at >= today_start).limit(_MAX_DAILY_CHALLENGES)
        return [{"challenge_id": c.id, "question": c.question, "score": c.score, "completed": bool(c.completed_at)} for c in challenges]
    except Exception as e:
        log_event(f"[ERROR] Fetching challenges failed: {str(e)}", level="ERROR")
        return []

def generate_social_challenge(from_user: str, to_user: str, mode: str = "vs") -> Dict:
    try:
        data = generate_challenge(mode, "en")
        encrypted_answer = _encrypt_challenge_data(data["answer"])
        challenge_id = _generate_secure_challenge_id(from_user)
        for user in [from_user, to_user]:
            Challenge.create(
                id=challenge_id, user_id=user, type="social", question=data["question"],
                answer=encrypted_answer, lang="en", created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + _CHALLENGE_TTL, status="active",
                hmac=_generate_hmac(data["question"]).hex()
            )
        log_event(f"CHALLENGE_SOCIAL_CREATED:{challenge_id}:{from_user} vs {to_user}")
        return {"challenge_id": challenge_id, "question": data["question"]}
    except Exception as e:
        log_event(f"[ERROR] Social challenge failed: {str(e)}", level="ERROR")
        return {"status": "error"}

def adjust_difficulty(user_id: str) -> str:
    try:
        recent = Challenge.select().where(Challenge.user_id == user_id).order_by(Challenge.created_at.desc()).limit(10)
        recent_list = list(recent)
        if recent_list:
            avg_score = sum(c.score for c in recent_list if c.score is not None) / len(recent_list)
        else:
            avg_score = 0.5
        if avg_score > 0.8:
            return "hard"
        elif avg_score > 0.5:
            return "medium"
        return "easy"
    except Exception as e:
        log_event(f"[ERROR] Difficulty adjustment failed: {str(e)}", level="ERROR")
        return "medium"

def get_active_challenges(user_id: str) -> List[Dict]:
    try:
        now = datetime.utcnow()
        challenges = Challenge.select().where(
            Challenge.user_id == user_id, Challenge.status == "active", Challenge.expires_at > now
        )
        return [{"challenge_id": c.id, "question": c.question, "type": c.type, "created_at": c.created_at.isoformat(), "expires_at": c.expires_at.isoformat()} for c in challenges]
    except Exception as e:
        log_event(f"[ERROR] Fetching active challenges failed: {str(e)}", level="ERROR")
        return []

def expire_old_challenges() -> None:
    try:
        now = datetime.utcnow()
        expired = Challenge.update(status="expired").where((Challenge.status == "active") & (Challenge.expires_at < now))
        expired.execute()
    except Exception as e:
        log_event(f"[ERROR] Expiring challenges failed: {str(e)}", level="ERROR")

def get_leaderboard(top_n: int = 10) -> List[Dict]:
    try:
        users = UserProfile.select().order_by(UserProfile.xp.desc()).limit(top_n)
        return [{"user_id": u.id, "xp": u.xp, "coins": u.coins} for u in users]
    except Exception as e:
        log_event(f"[ERROR] Fetching leaderboard failed: {str(e)}", level="ERROR")
        return []