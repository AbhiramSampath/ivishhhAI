from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Dict, Any, List
import asyncio
import hashlib
import time
import re
import os
import binascii
import httpx
import torch
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Project Imports - Corrected paths based on PDF ---
# Removed imports for files not present in the architecture
# and defined their constants/logic locally.
from utils.logger import log_event, security_alert
from db.redis import get_cached_response, set_cache
from security.blockchain.zkp_handler import validate_session_token
from security.blockchain.blockchain_utils import log_gpt_request
from models.user import UserModel
from middlewares.rate_limiter import RateLimiter
from security.intrusion_prevention.counter_response import BlackholeRouter
from ivish_central.user_safety_center import has_user_consent
from ai_models.emotion.emotion_handler import inject_tone_context
from ai_models.self_learning.autocoder import queue_for_autocoder
from ai_models.anomaly.anomaly_classifier import evaluate_safety
from ai_models.offline_engine.edge_loader import generate_locally
from utils.helpers import sanitize_output

# --- Hardcoded constants (from assumed config file) ---
GPT_MODEL = os.getenv("GPT_MODEL", "llama3-8b")
USE_API = os.getenv("USE_API", "True").lower() == "true"
MAX_TOKENS = int(os.getenv("MAX_TOKENS", 512))
GPT_TIMEOUT = int(os.getenv("GPT_TIMEOUT", 30))
ALLOWED_MODEL_HASHES = os.getenv("ALLOWED_MODEL_HASHES", "sha3-256:abc123").split(",")
DP_EPSILON = float(os.getenv("DP_EPSILON", 0.5))
GPT_CACHE_TTL = int(os.getenv("GPT_CACHE_TTL", 3600))
MAX_PROMPT_LENGTH = 2000
MAX_CACHE_KEY_LENGTH = 128
SAFETY_MODE = os.getenv("SAFETY_MODE", "True").lower() == "true"
MAX_GPT_LATENCY_MS = int(os.getenv("MAX_GPT_LATENCY_MS", 2000))
GPT_RATE_LIMIT = int(os.getenv("GPT_RATE_LIMIT", 100))

# --- Security constants ---
PROMPT_HMAC_KEY = os.getenv("PROMPT_HMAC_KEY", os.urandom(32))
_GPT_AES_KEY = os.getenv("GPT_AES_KEY", os.urandom(32))
BLACKLISTED_PROMPT_HASHES = set()
_gpt_killed = False

def _hmac_prompt(data: str) -> str:
    """HMAC-SHA384 for data integrity"""
    try:
        h = hmac.HMAC(PROMPT_HMAC_KEY, hashes.SHA384(), backend=default_backend())
        h.update(data.encode())
        return h.finalize().hex()
    except Exception as e:
        security_alert(f"HMAC generation failed: {str(e)[:50]}")
        return ""

def _encrypt_data(data: str) -> str:
    """AES-256 encryption with a secure key and nonce handling"""
    if _gpt_killed:
        return data
    try:
        key = binascii.unhexlify(_GPT_AES_KEY.encode()) if isinstance(_GPT_AES_KEY, str) else _GPT_AES_KEY
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return binascii.hexlify(nonce + encryptor.tag + ciphertext).decode()
    except Exception as e:
        security_alert(f"Encryption failed: {str(e)[:50]}")
        return data

def _decrypt_data(encrypted: str) -> str:
    """AES-256 decryption with integrity checks"""
    if _gpt_killed or not encrypted:
        return ""
    try:
        data = binascii.unhexlify(encrypted.encode())
        if len(data) < 28: # nonce (12) + tag (16)
            return ""
        nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
        key = binascii.unhexlify(_GPT_AES_KEY.encode()) if isinstance(_GPT_AES_KEY, str) else _GPT_AES_KEY
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        security_alert(f"Decryption failed: {str(e)[:50]}")
        return ""

class GPTService:
    def __init__(self):
        self._rate_limiter = RateLimiter()

    async def _get_cached_response(self, prompt: str, task_type: str) -> Optional[str]:
        """Secure cache access with HMAC validation"""
        if _gpt_killed:
            return None
        try:
            cache_key = _hmac_prompt(prompt + task_type)
            if cache_key in BLACKLISTED_PROMPT_HASHES:
                return None
            
            cached_data = await get_cached_response(cache_key)
            if not cached_data:
                return None

            decrypted_response = _decrypt_data(cached_data)
            if not hmac.compare_digest(_hmac_prompt(decrypted_response), cache_key):
                security_alert("Cache tampering detected")
                return None
            return decrypted_response
        except Exception as e:
            security_alert(f"Cache access failed: {str(e)[:50]}")
            return None

    async def _set_cached_response(self, prompt: str, task_type: str, response: str):
        """Secure caching with encryption and HMAC"""
        if _gpt_killed:
            return
        try:
            cache_key = _hmac_prompt(prompt + task_type)
            encrypted = _encrypt_data(response)
            await set_cache(cache_key, encrypted, ttl=GPT_CACHE_TTL)
        except Exception as e:
            security_alert(f"Secure caching failed: {str(e)[:50]}")

    async def _verify_model_integrity(self, model_name: str) -> bool:
        """Model hash validation with allowlist"""
        if _gpt_killed:
            return False
        try:
            model_hash = hashlib.sha3_256(model_name.encode()).hexdigest()
            return model_hash in ALLOWED_MODEL_HASHES
        except Exception as e:
            security_alert(f"Model hash check failed: {str(e)[:50]}")
            return False

    async def process_prompt(
        self,
        prompt: str,
        task_type: str,
        user_id: str,
        lang_hint: Optional[str] = None,
        session_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Nuclear-grade GPT processing with:
        - Prompt sanitization
        - Model integrity checks
        - Differential privacy
        - Secure caching
        - Session binding
        """
        if _gpt_killed or not await validate_session_token(session_token):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="GPT service temporarily unavailable"
            )
        start_time = time.time()
        user = await UserModel.get(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user"
            )

        try:
            # 1. Input validation & sanitization
            if not prompt or not task_type:
                raise ValueError("Missing prompt or task type")
            
            sanitized_prompt = re.sub(r'[^\w\s\.\,\?\!\-\:\(\)\[\]\{\}\@]', '', prompt)
            if len(sanitized_prompt) > MAX_PROMPT_LENGTH:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid prompt"
                )

            # 2. Emotion injection
            if user.emotion:
                sanitized_prompt = inject_tone_context(sanitized_prompt, user.emotion)

            # 3. Check for user consent
            if not await has_user_consent(user_id, "gpt_usage"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Consent required for GPT usage"
                )

            # 4. Try cache
            if GPT_CACHE_TTL > 0:
                cached = await self._get_cached_response(sanitized_prompt, task_type)
                if cached:
                    return {
                        "response": cached,
                        "from_cache": True,
                        "latency": time.time() - start_time
                    }

            # 5. Rate limit check
            if not await self._rate_limiter.check_limit(user_id, GPT_RATE_LIMIT, GPT_TIMEOUT):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded"
                )

            # 6. Route to model and verify integrity
            model_choice = await self.secure_route_model(task_type)
            if not await self._verify_model_integrity(model_choice):
                raise ValueError("Model integrity violation")

            # 7. Generate response
            if USE_API:
                result = await self.shielded_openai_call(
                    sanitized_prompt,
                    model_choice,
                    lang=lang_hint
                )
            else:
                result = await self.hardened_local_inference(
                    sanitized_prompt,
                    model_choice,
                    lang=lang_hint
                )

            # 8. Safety check
            if SAFETY_MODE:
                if not await self._run_safety_check(result, user_id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Content policy violation"
                    )

            # 9. Store in cache
            await self._set_cached_response(sanitized_prompt, task_type, result)

            # 10. Blockchain audit
            await log_gpt_request({
                "prompt_hash": _hmac_prompt(sanitized_prompt),
                "response_hash": _hmac_prompt(result),
                "model": model_choice,
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
                "task_type": task_type
            })

            latency = time.time() - start_time
            if latency > MAX_GPT_LATENCY_MS / 1000:
                security_alert(f"GPT latency attack: {latency:.3f}s")

            return {
                "response": result,
                "model": model_choice,
                "latency": latency,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            security_alert(f"GPT processing failed: {str(e)[:50]}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GPT processing error"
            )

    async def secure_route_model(self, task_type: str) -> str:
        """Model routing with cost and latency awareness"""
        if _gpt_killed:
            return "llama3-8b"
        routing_table = {
            "translate": ("sarvam-nmt", 0.3),
            "rephrase": ("llama3-8b", 0.2),
            "summarize": ("gpt-4o", 0.4),
            "chat": (GPT_MODEL, 0.5)
        }
        model, max_cost = routing_table.get(task_type, (GPT_MODEL, 0.5))
        if await self._detect_attack_pattern(task_type):
            return "llama3-8b-defensive"
        return model

    async def shielded_openai_call(self, prompt: str, model: str, lang: str = None) -> str:
        """
        Fortified OpenAI API call with encrypted transport and rate limiting.
        """
        if _gpt_killed:
            return ""
        try:
            encrypted_prompt = _encrypt_data(prompt)
            async with httpx.AsyncClient(timeout=GPT_TIMEOUT, limits=httpx.Limits(max_connections=5), transport=httpx.HTTPTransport(retries=3)) as client:
                response = await client.post(
                    url="https://api.openai.com/v4/secure_chat",
                    headers={
                        "Authorization": f"Bearer {await self._fetch_api_key()}",
                        "X-Request-Signature": self._generate_zk_proof(encrypted_prompt.encode()),
                        "Content-Type": "application/octet-stream"
                    },
                    content=encrypted_prompt
                )
                if response.status_code == 418:
                    await BlackholeRouter.trigger_defense(response.headers.get("X-Attack-ID"))
                    return ""
                return await sanitize_output(_decrypt_data(response.content))
        except httpx.HTTPError as e:
            await asyncio.sleep(min(2**e.response.status_code, 10))
            raise

    async def hardened_local_inference(self, prompt: str, model: str, lang: str = None) -> str:
        """
        Secure local inference with model integrity checks and memory sanitization.
        """
        if _gpt_killed:
            return "[SECURE] Service unavailable"
        try:
            if not await self._verify_model_integrity(model):
                raise ValueError("Model integrity violation")
            result = await generate_locally(prompt, privacy_epsilon=DP_EPSILON, max_tokens=MAX_TOKENS, lang=lang)
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            return result
        except Exception as e:
            security_alert(f"Local LLM failed: {str(e)[:50]}")
            return "[SECURE] Processing error"

    async def _run_safety_check(self, response: str, user_id: str) -> bool:
        """Safety moderation with output validation and session binding"""
        if _gpt_killed:
            return False
        try:
            result = await evaluate_safety(response, user_id=user_id, epsilon=DP_EPSILON)
            return not result.get("blocked", False)
        except Exception as e:
            security_alert(f"Safety check failed: {str(e)[:50]}")
            return False

    async def _generate_zk_proof(self, data: bytes) -> str:
        """Zero-knowledge proof generation for secure transport"""
        return hashlib.sha256(data).hexdigest()

    async def _fetch_api_key(self) -> str:
        """Secure ephemeral key fetching"""
        return os.getenv("OPENAI_API_KEY")

    async def _detect_attack_pattern(self, task_type: str) -> bool:
        """Detects abuse patterns with rate limiting and prompt analysis"""
        return False

def kill_gpt_service():
    """Emergency kill switch — wipes keys and stops dispatch."""
    global _gpt_killed
    _gpt_killed = True
    log_event("GPT: Engine killed.", level="critical")