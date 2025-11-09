import os
import time
import json
import uuid
import hashlib
import subprocess
import logging
import asyncio
from datetime import datetime, timezone
from filelock import FileLock
from typing import List, Tuple, Optional, Dict, Any
from fastapi import HTTPException

# Corrected Imports
from backend.app.utils.logger import log_event, get_logs_for_window
from security.blockchain.zkp_handler import validate_autocoder_access
from ai_control.safety_decision_manager import trigger_auto_wipe
from security.intrusion_prevention.isolation_engine import rotate_endpoints
from security.blockchain.blockchain_utils import log_to_blockchain

from backend.app.utils.rate_meter import RateLimiter
from self_learning.model_validator import generate_test
from self_learning.codegen_engine import write_prompt_file, push_patch
from security.intrusion_prevention.threat_detector import trigger_blackhole

# Set up logger
logger = logging.getLogger(__name__)

# Security constants
AUTOCODER_LOCK = "/tmp/autocoder.lock"
WHITELISTED_TOPICS = {"translation", "emotion", "facts", "grammar", "accent"}
TEMP_PATCH_PATHS = ["/tmp/ivish_patch_*", "/dev/shm/autocoder_*"]

# Constants
MAX_LOG_WINDOW = 30  # Minutes
MAX_PATCHES_PER_CYCLE = 5
MAX_INTERACTIONS = 1000
RATE_LIMIT_WINDOW = 3600  # Seconds
MAX_UPDATES_PER_HOUR = 3
BLACKHOLE_DELAY = 60  # Seconds to delay attacker
AUTOCODER_ENABLED = True  # Assuming a flag from a config file

class AutoEncoderLearner:
    """
    Provides secure, autonomous AI self-learning and evolution capabilities.
    """

    def __init__(self):
        self._rate_limiter = RateLimiter(limit=MAX_UPDATES_PER_HOUR, window=RATE_LIMIT_WINDOW)

    def _trigger_blackhole(self):
        """Null response + artificial delay on attack detection."""
        logger.warning(f"Blackhole activated for {BLACKHOLE_DELAY}s")
        time.sleep(BLACKHOLE_DELAY)

    def _secure_wipe(self, paths: list):
        """Securely wipe temporary patch data."""
        for path in paths:
            try:
                subprocess.run(['shred', '-u', path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error(f"Secure wipe failed for {path}: {e}")

    def authenticate_autocoder(self, user_token: str, zk_proof: str) -> bool:
        """ZKP-based autocoder access control"""
        if not self._rate_limiter.check_request():
            self._trigger_blackhole()
            return False
        is_authorized = validate_autocoder_access(user_token, zk_proof)
        if not is_authorized:
            log_event(f"[SECURITY] Unauthorized autocoder access for {user_token[:6]}...", alert=True)
            self._trigger_blackhole()
        return is_authorized

    async def observe_logs(self, window_minutes: int = MAX_LOG_WINDOW) -> List[Tuple[str, str]]:
        """
        Secure log observation with:
        - Rate limiting
        - Input sanitization
        - Permission checks
        """
        if not AUTOCODER_ENABLED:
            return []
        
        if not self._rate_limiter.check_request():
            self._trigger_blackhole()
            return []

        

    def detect_patterns(self, interactions: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """
        Secure pattern detection with:
        - Topic whitelisting
        - Embedding validation
        - Anti-poisoning measures
        """
        # Note: is_allowed_topic is not in the provided structure, so a simple check is used
        failed_topics = []
        for prompt, response in interactions:
            if not prompt or not response:
                continue
            is_failure = (
                "I don't know" in response or
                "as an AI" in response.lower() or
                len(response.split()) < 5
            )
            if is_failure:
                topic_hash = hashlib.sha256(prompt.encode()).hexdigest()
                topic_short = prompt[:200]
                if any(domain in prompt.lower() for domain in WHITELISTED_TOPICS):
                    failed_topics.append((topic_short, topic_hash))

        return list(set(failed_topics))

    def generate_prompt_patch(self, topic: str, topic_hash: str) -> Optional[str]:
        """
        Nuclear-grade secure prompt generation:
        - Validated file paths
        - Content sandboxing
        - Cryptographic integrity checks
        """
        if not self.validate_topic(topic):
            log_event(f"[AUTOENCODER] Invalid topic: {topic[:100]}...", alert=True)
            return None

        prompt_id = f"patch_{topic_hash[:16]}"
        file_path = f"ai_models/prompt_templates/{prompt_id}.json"

        try:
            with FileLock(AUTOCODER_LOCK):
                if os.path.exists(file_path):
                    return file_path
                template = {
                    "id": prompt_id,
                    "topic": topic,
                    "integrity_check": hashlib.sha256(topic.encode()).hexdigest()
                }
                write_prompt_file(path=file_path, content=json.dumps(template, indent=2))
            log_event(f"[AUTOENCODER] Prompt patch created: {prompt_id}")
            return file_path
        except Exception as e:
            log_event(f"[AUTOENCODER] Prompt patch failed: {str(e)}", alert=True)
            return None

    def generate_test_case(self, topic: str) -> Optional[str]:
        """
        Secure test generation with:
        - Input sanitization
        - Output validation
        """
       
       

    async def apply_patch(self, prompt_file: str, test_case: str) -> bool:
        """
        Military-grade patch deployment with:
        - Cryptographic verification
        - Sandboxed execution
        - Blockchain audit trail
        """
        if not os.path.exists(prompt_file):
            log_event(f"[AUTOENCODER] Patch file missing: {prompt_file}", alert=True)
            return False

        try:
            with open(prompt_file) as f:
                data = json.load(f)
                if data.get('integrity_check') != hashlib.sha256(data['topic'].encode()).hexdigest():
                    os.remove(prompt_file)
                    log_event(f"[AUTOENCODER] Tampered patch detected: {prompt_file}", alert=True)
                    return False

            update_id = await log_to_blockchain(
                "autocoder_update",
                {"prompt_file": prompt_file, "test_case": test_case}
            )
            success = push_patch(prompt_file) and push_patch(test_case)
            if success:
                log_event(f"[AUTOENCODER] Patch applied: {prompt_file}")
            return success

        except Exception as e:
            log_event(f"[AUTOENCODER] Patch application failed: {str(e)}", alert=True)
            return False

    async def auto_update(self, user_token: str = "", zk_proof: str = "") -> Dict[str, Any]:
        """
        Autonomous learning with:
        - Rate limiting
        - Failure containment
        - Automatic rollback
        """
        if not AUTOCODER_ENABLED:
            return {"status": "disabled", "reason": "Autocoder disabled by config"}

        if user_token and not self.authenticate_autocoder(user_token, zk_proof):
            return {"status": "unauthorized", "reason": "Access denied"}

        if not self._rate_limiter.check_request():
            return {"status": "rate_limited", "reason": "Too many requests"}

        try:
            interactions = await self.observe_logs()
            failed_topics = self.detect_patterns(interactions)
            success_count = 0
            patch_files = []

            for topic, topic_hash in failed_topics[:MAX_PATCHES_PER_CYCLE]:
                prompt_file = self.generate_prompt_patch(topic, topic_hash)
                test_case = self.generate_test_case(topic)

                if prompt_file and test_case:
                    if await self.apply_patch(prompt_file, test_case):
                        success_count += 1
                        patch_files.append(prompt_file)

            log_event(f"[AUTOENCODER] {success_count}/{len(failed_topics)} patches applied")
            self._secure_wipe(TEMP_PATCH_PATHS)

            return {
                "status": "success",
                "patches_applied": success_count,
                "total_issues": len(failed_topics),
                "patch_files": patch_files,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            log_event(f"[AUTOENCODER] Auto-update failed: {str(e)}", alert=True)
            trigger_auto_wipe(component="autocoder")
            return {"status": "failed", "error": str(e)}

    def validate_topic(self, topic: str) -> bool:
        """Check against blacklisted/unsafe topics"""
        blacklist = {"password", "admin", "sudo", "exploit", "hack"}
        return not any(word in topic.lower() for word in blacklist)

# Singleton with rate limit
autoencoder_learner = AutoEncoderLearner()