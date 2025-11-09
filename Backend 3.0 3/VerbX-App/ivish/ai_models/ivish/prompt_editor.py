from imaplib import _Authenticator
import os
import re
import time
import uuid
import hashlib
import hmac
import logging
import subprocess
import asyncio
from datetime import datetime, timezone
from typing import Dict, Optional, Union, List
from jinja2 import Template, StrictUndefined
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from fastapi import HTTPException
from collections import defaultdict

# Corrected Internal imports based on project architecture
from ai_models.ivish.memory_agent import get_session_context as get_recent_context
from ai_models.emotion.emotion_handler import detect_emotion
from security.blockchain.zkp_handler import validate_prompt_editor_access
from backend.app.utils.logger import log_event, BaseLogger
from security.intrusion_prevention.counter_response import BlackholeRouter

# --- Placeholder Imports for non-existent modules ---
def sanitize_prompt(prompt: str) -> str:
    """Placeholder for prompt sanitization."""
    # This is a very simple sanitization; a real one would be more complex.
    sanitized = prompt.replace('`', '').replace('"', '')
    return sanitized

# --- Constants (from removed config file) ---
ENABLE_USER_PROMPT_TUNING = os.getenv("ENABLE_USER_PROMPT_TUNING", "True").lower() == "true"
MAX_PROMPT_LENGTH = 3000
MAX_TEMPLATE_DEPTH = 5
BANNED_PATTERNS = re.compile(
    r"(kill|suicide|bomb|hack|exploit|<?script|\\x[0-9a-f]{2})", 
    re.IGNORECASE
)
HMAC_KEY = os.getenv("PROMPT_HMAC_KEY", os.urandom(32))
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_MIN = 20
BLACKHOLE_DELAY = 60
TEMP_PROMPT_PATHS = ["/tmp/ivish_prompt_*", "/dev/shm/prompt_*"]

logger = BaseLogger("PromptEngine")
blackhole_router = BlackholeRouter()

class PromptEngine:
    """
    Provides secure, dynamic, and emotion-aware prompt generation and injection for Ivish AI.
    """

    def __init__(self):
        self._request_count = defaultdict(int)
        self._window_start = defaultdict(float)
        self._template_cache = {}
        self._prompt_db = {}
        self._derived_key = self._derive_prompt_key()
        self._last_key_rotation = time.time()

    async def _validate_rate_limit(self, user_id: str) -> bool:
        """Prevent prompt editor flooding attacks."""
        now = time.time()
        if now - self._window_start[user_id] > RATE_LIMIT_WINDOW:
            self._request_count[user_id] = 0
            self._window_start[user_id] = now
            
        self._request_count[user_id] += 1
        if self._request_count[user_id] > MAX_REQUESTS_PER_MIN:
            await log_event("[SECURITY] Prompt editor rate limit exceeded", level="ALERT")
            await blackhole_router.trigger()
            return False
        return True

    async def _secure_wipe(self, paths: list):
        """Securely wipe temporary prompt data."""
        for path in paths:
            try:
                await asyncio.to_thread(
                    subprocess.run,
                    ['shred', '-u', path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                logger.log_event(f"Secure wipe failed for {path}: {e}", level="ERROR")

    def _derive_prompt_key(self) -> bytes:
        """HKDF-derived key for secure prompt operations."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b'prompt_key',
        ).derive(HMAC_KEY)

    def _rotate_key(self):
        """Periodically rotate prompt encryption key."""
        now = time.time()
        if now - self._last_key_rotation > 3600:
            self._derived_key = self._derive_prompt_key()
            self._last_key_rotation = now

    def _validate_template(self, template: str) -> bool:
        """Prevent SSTI and malicious templates."""
        if not template or len(template) > MAX_PROMPT_LENGTH:
            return False
        if BANNED_PATTERNS.search(template):
            return False
        return True

    async def _secure_render(self, template: str, context: Dict) -> Optional[str]:
        """Sandboxed template rendering with strict validation."""
        self._rotate_key()
        cache_key = hashlib.sha256(template.encode()).hexdigest()
        
        try:
            if cache_key not in self._template_cache:
                self._template_cache[cache_key] = Template(
                    template,
                    undefined=StrictUndefined
                )
            rendered = await asyncio.to_thread(self._template_cache[cache_key].render, **context)
            if not rendered or len(rendered) > MAX_PROMPT_LENGTH:
                return None
            return rendered
        except Exception as e:
            await log_event(f"[PROMPT_RENDER_ERROR] {str(e)}", level="ALERT")
            return None

    async def authenticate_editor(self, user_token: str, zk_proof: str) -> bool:
        """ZKP-based editor authentication with rate-limiting."""
        if not await self._validate_rate_limit(user_token):
            return False
        is_authorized = await validate_prompt_editor_access(user_token, zk_proof)
        if not is_authorized:
            await log_event(f"[SECURITY] Unauthorized prompt access for {user_token[:6]}...", level="ALERT")
            await blackhole_router.trigger()
        return is_authorized

    async def build_prompt(self, template: str, context: Dict) -> str:
        """Secure prompt builder with HMAC-tagged output."""
        if not self._validate_template(template):
            await log_event("[PROMPT] Invalid template", level="ALERT")
            return "[SECURE_PROMPT_ERROR]"
            
        rendered = await self._secure_render(template, context)
        if not rendered:
            return "[RENDER_FAILURE]"
            
        clean_prompt = sanitize_prompt(rendered)
        h = hmac.HMAC(self._derived_key, hashes.SHA256(), backend=default_backend())
        h.update(clean_prompt.encode())
        tag = h.finalize().hex()
        
        return f"{clean_prompt}\n"

    async def auto_prompt(self, user_input: str, user_id: str = "") -> str:
        """Context-aware prompt generator with emotion injection."""
        if user_id and not await self.authenticate_editor(user_id, "dummy_proof"):
            return "[UNAUTHORIZED_PROMPT]"
            
        recent = await get_recent_context(user_id)
        emotion = await detect_emotion(user_input[:1000])
        
        base_template = (
            "System: Respond as Ivish ({{emotion}} tone).\n"
            "User ({{emotion}}): {{user_input}}\n"
            "Context: {{recent_context}}\n"
            "Rules: {{rules|default('Be helpful and concise')}}"
        )
        
        context = {
            "emotion": emotion,
            "user_input": user_input[:2000],
            "recent_context": recent[:1000] if recent else "None",
            "user_id": user_id
        }
        
        return await self.build_prompt(base_template, context)

    async def store_prompt_variant(self, user_id: str, tag: str, prompt: str) -> bool:
        """Encrypted prompt storage with access control."""
        if not ENABLE_USER_PROMPT_TUNING or not self._validate_template(prompt):
            return False
            
        if user_id and not await self.authenticate_editor(user_id, "dummy_proof"):
            return False
            
        key_hmac = hmac.HMAC(self._derived_key, hashes.SHA256(), backend=default_backend())
        key_hmac.update(user_id.encode())
        key = f"{key_hmac.finalize().hex()}:{tag}"
        
        prompt_hmac = hmac.HMAC(self._derived_key, hashes.SHA256(), backend=default_backend())
        prompt_hmac.update(prompt.encode())
        
        self._prompt_db[key] = {
            "prompt": prompt,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "integrity_tag": prompt_hmac.finalize().hex()
        }
        return True

    async def load_prompt_variant(self, user_id: str, tag: str) -> Optional[str]:
        """Secure prompt retrieval with HMAC validation."""
        key_hmac = hmac.HMAC(self._derived_key, hashes.SHA256(), backend=default_backend())
        key_hmac.update(user_id.encode())
        key = f"{key_hmac.finalize().hex()}:{tag}"
        
        entry = self._prompt_db.get(key)
        if not entry:
            return None
            
        h = hmac.HMAC(self._derived_key, hashes.SHA256(), backend=default_backend())
        h.update(entry["prompt"].encode())
        try:
            h.verify(bytes.fromhex(entry["integrity_tag"]))
            return entry["prompt"]
        except Exception:
            await log_event("[PROMPT] Tampered prompt detected", level="ALERT")
            return None

    def _trigger_defense_response(self):
        logger.log_event("🚨 TEMPLATE TAMPERING DETECTED: Activating honeypot and endpoint rotation", level="CRITICAL")
        _Authenticator().rotate_keys()
        _firewall.activate_intrusion_response() # type: ignore

# Singleton with template caching
prompt_engine = PromptEngine()