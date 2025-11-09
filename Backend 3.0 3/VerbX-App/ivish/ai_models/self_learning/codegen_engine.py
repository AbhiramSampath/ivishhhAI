"""
codegen_engine.py - AutoCoder: AI-Powered Code Evolution Engine

The self-learning engine of Ivish AI that observes usage, learns patterns,
and autonomously generates, improves, and refactors backend routes, transformers, and prompts.
"""

import os
from pathlib import Path
import tempfile
import uuid
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import hashlib
import logging
import re
import shutil
import glob
import json

# --- Placeholder Imports for non-existent modules ---
def create_temp_branch(branch_name: str) -> str:
    """Placeholder for creating a temporary Git branch."""
    logging.info(f"Placeholder: Created Git branch '{branch_name}'")
    return branch_name

def commit_code_to_branch(branch_name: str, file_path: str, message: str):
    """Placeholder for committing code to a Git branch."""
    logging.info(f"Placeholder: Committed '{file_path}' to '{branch_name}'")

def fetch_recent_usage(limit: int) -> List[Dict]:
    """Placeholder for fetching usage logs."""
    return [
        {"module": "chat.py", "tags": ["slow"], "failures": 3, "timestamp": "2023-10-27T10:00:00Z"},
        {"module": "ner.py", "tags": ["security_alert"], "failures": 1, "timestamp": "2023-10-27T10:00:00Z"},
    ]

def improve_prompt(description: str) -> str:
    """Placeholder for prompt optimization."""
    return f"Refactor code to address: {description}"

def scan_code_for_vulnerabilities(code: str) -> bool:
    """Placeholder for static code analysis."""
    return False

class SessionManager:
    """Placeholder for a session manager."""
    pass

class AuditAgent:
    """Placeholder for an audit agent."""
    pass

class SecureCodegenContext:
    """Placeholder for a secure sandbox."""
    def __enter__(self):
        pass
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

class CircuitBreaker:
    """Placeholder for a circuit breaker."""
    def __init__(self, threshold: int, cooldown: int):
        pass
    def trigger(self):
        logging.warning("Placeholder: Circuit breaker triggered")

# Corrected Internal imports based on project architecture
from backend.app.utils.logger import log_event, BaseLogger
from ai_models.self_learning.model_validator import validate_code
from ai_models.translation.gpt_prompter import gpt_generate_code
from security.blockchain.blockchain_utils import log_to_blockchain
from security.intrusion_prevention.counter_response import BlackholeRouter

# External imports

# Type aliases
CodegenTask = Dict[str, Any]
CodegenResult = Dict[str, Any]

# Security: Rate limiter to prevent runaway generation
_MAX_GENERATIONS_PER_HOUR = int(os.getenv("MAX_GENERATIONS_PER_HOUR", "20"))
_GENERATION_COUNTER = 0
_LAST_RUN_TIMESTAMP = None
_CODEGEN_TOKENS_LIMIT = int(os.getenv("CODEGEN_TOKENS_LIMIT", "512"))
_STAGING_PATH = os.getenv("STAGING_PATH", "./codegen_staging")

logger = BaseLogger("CodegenEngine")

class CodegenEngine:
    """
    AI-powered code evolution engine for Ivish AI.
    """

    def __init__(self):
        self._session_manager = SessionManager()
        self._audit_agent = AuditAgent()
        self._circuit_breaker = CircuitBreaker(threshold=3, cooldown=60)
        self._supported_tasks = ["route", "transformer", "prompt", "test", "utility"]
        self._code_blacklist = self._load_code_blacklist()
        self._session_key = self._generate_session_key()
        self._blackhole_router = BlackholeRouter()

    def run(self):
        """SECURITY: Wrapped in execution sandbox with rate limiting"""
        global _GENERATION_COUNTER, _LAST_RUN_TIMESTAMP

        current_time = datetime.utcnow()
        if self._rate_limited(current_time):
            logger.log_event("AutoCoder rate limited ⚠️", level="WARNING")
            return

        logger.log_event("AutoCoder started 🚀", level="INFO")
        try:
            with SecureCodegenContext():
                usage_data = self._analyze_usage()
                tasks = self._suggest_improvements(usage_data)

                for task in tasks:
                    if self._rate_limited(current_time):
                        break

                    logger.log_event(f"AutoCoder generating: {task['title']}", level="INFO")
                    prompt = improve_prompt(task["description"])

                    if not self._is_prompt_safe(prompt):
                        continue

                    generated_code = self._generate_code(task["type"], prompt)

                    if not self._is_code_safe(generated_code):
                        logger.log_event("AutoCoder rejected unsafe code 🛑", level="WARNING")
                        self._blackhole_router.trigger()
                        continue

                    file_path = self._stage_code(task["filename"], generated_code)
                    valid = self._validate_code(file_path)

                    self._log_codegen_event({
                        "task": task["title"],
                        "timestamp": current_time.isoformat(),
                        "validated": valid,
                        "file": file_path,
                        "fingerprint": self._generate_fingerprint(generated_code),
                    })

            logger.log_event("AutoCoder finished ✅", level="INFO")
        except Exception as e:
            logger.log_event("AutoCoder failed: Security sandbox enforced 🔒", level="ERROR", exc_info=e)
            self._circuit_breaker.trigger()

    def _rate_limited(self, current_time: datetime) -> bool:
        global _GENERATION_COUNTER, _LAST_RUN_TIMESTAMP
        if _LAST_RUN_TIMESTAMP is None or (current_time - _LAST_RUN_TIMESTAMP) >= timedelta(hours=1):
            _LAST_RUN_TIMESTAMP = current_time
            _GENERATION_COUNTER = 0
        
        if _GENERATION_COUNTER >= _MAX_GENERATIONS_PER_HOUR:
            return True
        
        _GENERATION_COUNTER += 1
        return False

    def _analyze_usage(self) -> List[Dict]:
        raw_data = fetch_recent_usage(limit=50)
        return [
            u for u in raw_data
            if isinstance(u, dict) and "module" in u and isinstance(u.get("tags", []), list)
        ]

    def _suggest_improvements(self, usage: List[Dict]) -> List[CodegenTask]:
        improvements = []
        for u in usage:
            if not isinstance(u, dict):
                continue
            if ("slow" in u.get("tags", []) or
                u.get("failures", 0) > 2 or
                "security_alert" in u.get("tags", [])):
                module_name = os.path.basename(u['module']).replace('.py', '')
                improvements.append({
                    "type": "route",
                    "title": f"Refactor module {module_name}",
                    "description": f"Improve {module_name} addressing: {', '.join(u['tags'])}",
                    "filename": f"{module_name}.py",
                    "security_context": {
                        "trigger": u.get("tags", []),
                        "risk_score": min(u.get("failures", 0) * 10, 100)
                    }
                })
        return improvements

    def _generate_code(self, task_type: str, prompt: str) -> str:
        if not self._is_prompt_safe(prompt):
            return ""
        return gpt_generate_code(
            task_type,
            prompt[:_CODEGEN_TOKENS_LIMIT * 4],
            max_tokens=_CODEGEN_TOKENS_LIMIT
        )

    def _stage_code(self, filename: str, code: str) -> str:
        try:
            if not filename.endswith('.py') or '/' in filename or '\\' in filename:
                raise ValueError("Invalid filename")
            
            temp_branch = create_temp_branch(f"autocoder-{uuid.uuid4().hex[:6]}")
            path = os.path.join(_STAGING_PATH, os.path.basename(filename))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            temp_file = Path(tempfile.NamedTemporaryFile(delete=False, dir=_STAGING_PATH).name)
            temp_file.write_text(code)
            shutil.move(str(temp_file), path)
            
            commit_code_to_branch(temp_branch, path, f"AutoCoder: {filename}")
            return path
        except Exception as e:
            logger.log_event(f"AutoCoder staging failed: {str(e)}", level="ERROR")
            return ""

    def _validate_code(self, file_path: str) -> bool:
        try:
            if not os.path.exists(file_path):
                return False
            if scan_code_for_vulnerabilities(file_path):
                return False
            if not validate_code(file_path):
                logger.log_event("AutoCoder rejected invalid code 🛑", level="WARNING")
                return False
            return True
        except Exception as e:
            logger.log_event(f"Code validation failed: {str(e)}", level="ERROR")
            return False

    def _log_codegen_event(self, data: Dict):
        if not isinstance(data, dict):
            return
        required = {"task", "timestamp", "file"}
        if not required.issubset(data.keys()):
            return
        
        event_data = {
            **data,
            "security": {
                "verified": data.get("validated", False),
                "system": "ivish-autocoder-v1",
                "audit_id": hashlib.sha256(str(data).encode()).hexdigest()
            }
        }
        
        logger.log_event(f"AUTOCODER LOG: {event_data}", level="INFO", security_level="high")
        log_to_blockchain("codegen_event", event_data)

    def _is_prompt_safe(self, prompt: str) -> bool:
        if len(prompt) > _CODEGEN_TOKENS_LIMIT * 4:
            return False
        if re.search(r"(\bexec\b|\beval\b|\bopen\b)", prompt):
            return False
        return True

    def _is_code_safe(self, code: str) -> bool:
        if not code:
            return False
        for unsafe in self._code_blacklist:
            if unsafe and re.search(rf"\b{re.escape(unsafe)}\b", code):
                return False
        if scan_code_for_vulnerabilities(code):
            return False
        return True

    def _generate_fingerprint(self, code: str) -> str:
        return hashlib.sha3_256(code.encode()).hexdigest()

    def _load_code_blacklist(self) -> List[str]:
        try:
            with open("security/code_blacklist.txt", "r") as f:
                return [line.strip() for line in f.readlines()]
        except Exception as e:
            logging.warning(f"Could not load code blacklist: {e}")
            return []

    def _generate_session_key(self) -> bytes:
        return os.urandom(32)

# Singleton instance
codegen_engine = CodegenEngine()