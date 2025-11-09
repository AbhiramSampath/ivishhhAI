# security/password_hasher.py

import os
import time
import hmac
import hashlib
import logging
import asyncio
import re
import secrets
from typing import Tuple, Dict, Optional, List, Union
from functools import lru_cache
from passlib.context import CryptContext
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Project Imports - CORRECTED PATHS
from utils.logger import log_event
from ai_models.ivish.memory_agent import MemorySessionHandler
from security.zkp_handler import ZeroKnowledgeProof
from security.intrusion_prevention.counter_response import BlackholeRouter

# Initialize secure components
logger = logging.getLogger(__name__)
memory_handler = MemorySessionHandler()
backend = default_backend()
blackhole_router = BlackholeRouter()

# Security Constants - Defined locally as config file is not in PDF
HASH_ALGORITHM = os.getenv("HASH_ALGORITHM", "argon2")
GLOBAL_PEPPER = os.getenv("GLOBAL_PEPPER", secrets.token_hex(32))
PEPPER_ROTATION_HOURS = int(os.getenv("PEPPER_ROTATION_HOURS", 24))
_SUPPORTED_HASHERS = {"argon2", "bcrypt", "scrypt", "pbkdf2_sha256"}
_ARGON2_PARAMS = {
    "time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 32, "salt_size": 16
}
_DEFAULT_ROUNDS = {
    "bcrypt": 14, "pbkdf2_sha256": 310000,
    "scrypt": {"n": 2**17, "r": 8, "p": 1, "maxmem": 2**25}
}
_MIN_PASSWORD_LENGTH = 8
_MAX_PASSWORD_LENGTH = 1024
_PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$')

hashers = CryptContext(
    schemes=["argon2", "bcrypt", "pbkdf2_sha256", "scrypt"],
    deprecated=["auto"],
    argon2__time_cost=_ARGON2_PARAMS["time_cost"],
    argon2__memory_cost=_ARGON2_PARAMS["memory_cost"],
    argon2__parallelism=_ARGON2_PARAMS["parallelism"],
    argon2__hash_len=_ARGON2_PARAMS["hash_len"],
    bcrypt__rounds=_DEFAULT_ROUNDS["bcrypt"],
    pbkdf2_sha256__rounds=_DEFAULT_ROUNDS["pbkdf2_sha256"],
    pbkdf2_sha256__salt_size=16,
    scrypt__n=_DEFAULT_ROUNDS["scrypt"]["n"],
    scrypt__r=_DEFAULT_ROUNDS["scrypt"]["r"],
    scrypt__p=_DEFAULT_ROUNDS["scrypt"]["p"],
    scrypt__maxmem=_DEFAULT_ROUNDS["scrypt"]["maxmem"]
)

class PepperVault:
    def __init__(self):
        self.current_pepper = GLOBAL_PEPPER
        self.previous_peppers = set()
        self.last_rotation = time.time()
        self._rotation_interval = PEPPER_ROTATION_HOURS * 3600

    def rotate(self) -> None:
        if time.time() - self.last_rotation < self._rotation_interval: return
        self.previous_peppers.add(self.current_pepper)
        self.current_pepper = secrets.token_hex(32)
        self.last_rotation = time.time()
        log_event("PEPPER: System pepper rotated", secure=True)

    def get_peppers(self) -> Tuple[str, set]:
        return (self.current_pepper, self.previous_peppers)

    def reset(self) -> None:
        self.previous_peppers.clear()
        self.current_pepper = GLOBAL_PEPPER
        self.last_rotation = time.time()
        log_event("PEPPER: System pepper reset", secure=True)

class PasswordSecurity:
    _pepper_vault = PepperVault()
    
    @classmethod
    def _apply_pepper(cls, password: str, pepper: str) -> str:
        return hmac.new(pepper.encode(), password.encode(), hashlib.sha256).hexdigest()

    @classmethod
    def hash_password(cls, plain_password: str) -> str:
        if not cls._validate_password(plain_password):
            log_event("AUTH: Weak password rejected", level="WARNING")
            raise ValueError("Password does not meet complexity requirements")

        cls._pepper_vault.rotate()
        current_pepper, _ = cls._get_peppers()
        peppered = cls._apply_pepper(plain_password, current_pepper)

        try:
            hashed = hashers.hash(peppered)
            log_event("AUTH: Password hashed with pepper rotation", secure=True)
            return hashed
        except Exception as e:
            log_event(f"AUTH: Hashing failed - {str(e)}", level="ERROR")
            raise

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        if not plain_password or not hashed_password: return False
        try:
            algorithm, _ = hashed_password.split('$', 1)
            if algorithm not in _SUPPORTED_HASHERS: return False
        except ValueError: return False

        current_pepper, previous_peppers = cls._get_peppers()
        peppered_passwords = [cls._apply_pepper(plain_password, current_pepper)]
        peppered_passwords.extend([cls._apply_pepper(plain_password, old_pepper) for old_pepper in previous_peppers])

        for peppered in peppered_passwords:
            if hashers.verify(peppered, hashed_password): return True
        return False

    @classmethod
    def needs_rehash(cls, hashed_password: str) -> bool:
        try:
            algorithm, _ = hashed_password.split('$', 1)
            if algorithm not in _SUPPORTED_HASHERS: return True
            return hashers.needs_update(hashed_password)
        except Exception as e:
            log_event(f"AUTH: Rehash check failed - {str(e)}", level="WARNING")
            return True

    @classmethod
    async def _async_rehash(cls):
        cls._pepper_vault.rotate()
        current_pepper, _ = cls._get_peppers()
        users = await memory_handler.list_all_users()
        for user in users:
            try:
                old_hash = user["password"]
                plain = cls._extract_plain_from_hash(old_hash, current_pepper)
                new_hash = cls.hash_password(plain)
                await memory_handler.update_user(user["id"], {"password": new_hash})
            except Exception as e:
                log_event(f"AUTH: Rehash failed for {user['id']} - {str(e)}", level="ERROR")

    @classmethod
    def _validate_password(cls, password: str) -> bool:
        if not password: return False
        if not (_MIN_PASSWORD_LENGTH <= len(password) <= _MAX_PASSWORD_LENGTH): return False
        if not _PASSWORD_REGEX.match(password): return False
        return True

    @classmethod
    def generate_recovery_token(cls, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        asyncio.create_task(memory_handler.store_recovery_token(user_id, token))
        return token

    @classmethod
    async def verify_recovery_token(cls, user_id: str, token: str) -> bool:
        stored = await memory_handler.get_recovery_token(user_id)
        return constant_time.compare_digest(token.encode(), stored.encode() if stored else b'')

    @classmethod
    async def enable_webauthn(cls, user_id: str, public_key: bytes) -> str:
        try:
            key_hash = hashlib.sha256(public_key).hexdigest()
            await memory_handler.store_webauthn_key(user_id, key_hash)
            return key_hash
        except Exception as e:
            log_event(f"WEBAUTHN: Key storage failed - {str(e)}", level="ERROR")
            return ""

    @classmethod
    async def verify_webauthn(cls, user_id: str, signature: bytes, challenge: bytes) -> bool:
        try:
            stored_key = await memory_handler.get_webauthn_key(user_id)
            return constant_time.compare_digest(hmac.new(stored_key.encode(), challenge, hashlib.sha256).digest(), signature)
        except Exception as e:
            log_event(f"WEBAUTHN: Verification failed - {str(e)}", level="WARNING")
            return False

password_hasher = PasswordSecurity()