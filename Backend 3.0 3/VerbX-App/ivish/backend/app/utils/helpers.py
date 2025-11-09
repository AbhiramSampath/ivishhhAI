# backend/utils/helpers.py
# 🔒 Final, Secure Utility Toolkit for Ivish AI

import os
import uuid
import time
import secrets
import hmac
import re
import logging
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional, Union
import asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Corrected imports based on folder structure
from .logger import log_event
from .security import sanitize_input_text

# Security: Constants for cryptographic operations
_TOKEN_HASH_ITERATIONS = 600_000
_MAX_RETRY_DELAY = 10.0
_DEFAULT_TIMEZONE = os.getenv("DEFAULT_TIMEZONE", "UTC")
_TOKEN_HASH_LENGTH = 32

logger = logging.getLogger("helper_toolkit")

def generate_secure_id(prefix: str = "id") -> str:
    """
    Generate a cryptographically secure ID.

    Args:
        prefix (str): Optional prefix for the ID (e.g., 'user', 'session').

    Returns:
        str: Unique, secure ID.
    """
    suffix = secrets.token_urlsafe(16)
    return f"{prefix}_{suffix}"

def current_time_iso() -> str:
    """
    Get the current UTC timestamp in ISO 8601 format.

    Returns:
        str: ISO 8601 formatted timestamp.
    """
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def format_duration(seconds: float) -> str:
    """
    Convert a duration in seconds to a human-readable format.

    Args:
        seconds (float): Duration in seconds.

    Returns:
        str: Formatted duration (e.g., "1m 3.5s").
    """
    total_ms = int(seconds * 1000)
    mins, ms = divmod(total_ms, 60000)
    secs, ms = divmod(ms, 1000)
    if mins > 0:
        return f"{mins}m {secs}.{ms:03d}s"
    return f"{secs}.{ms:03d}s"

def truncate_text(text: str, limit: int = 100) -> str:
    """
    Safe text truncation with Unicode awareness.

    Args:
        text (str): Input text.
        limit (int): Maximum length.

    Returns:
        str: Truncated text with an ellipsis.
    """
    if not isinstance(text, str):
        return ""
    if len(text) <= limit:
        return text
    return text[:limit-3] + "..."

def safe_get(d: Optional[Dict], key: Any, default: Any = None) -> Any:
    """
    Safely retrieve a value from a dictionary, returning a default if the key is
    not found or the input is not a dictionary.

    Args:
        d (dict): Dictionary to access.
        key (str): Key to retrieve.
        default (any): Fallback value.

    Returns:
        any: The value for the key or the default value.
    """
    if not isinstance(d, dict):
        return default
    return d.get(key, default)

def hash_token(token: str) -> (str, str):
    """
    PBKDF2-HMAC-SHA256 token hashing with a unique salt for each token.

    Args:
        token (str): Plaintext token.

    Returns:
        tuple[str, str]: A tuple containing the salt and the hashed token, both as hex strings.
    """
    if not token:
        return "", ""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_TOKEN_HASH_LENGTH,
        salt=salt,
        iterations=_TOKEN_HASH_ITERATIONS,
        backend=default_backend()
    )
    hashed_token = kdf.derive(token.encode()).hex()
    return salt.hex(), hashed_token

def constant_time_compare(a: str, b: str) -> bool:
    """
    Timing-attack resistant string comparison.

    Args:
        a (str): First string.
        b (str): Second string.

    Returns:
        bool: True if the strings are equal, False otherwise.
    """
    return secrets.compare_digest(a, b)

def async_retry(retries: int = 3, delay: float = 0.5, max_delay: float = _MAX_RETRY_DELAY):
    """
    Decorator for asynchronous functions with jittered exponential backoff.

    Args:
        retries (int): Max retry attempts.
        delay (float): Initial delay.
        max_delay (float): Max delay cap.

    Returns:
        Callable: Decorated function.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for attempt in range(1, retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == retries:
                        raise
                    jitter = 1 + (secrets.SystemRandom().random() - 0.5) * 0.1
                    sleep_time = min(delay * (2 ** (attempt - 1)) * jitter, max_delay)
                    logger.warning(f"Retrying '{func.__name__}' in {sleep_time:.2f}s (attempt {attempt}/{retries})...")
                    await asyncio.sleep(sleep_time)
        return wrapper
    return decorator

def time_it(func: Callable) -> Callable:
    """
    Decorator to time the execution of a function with nanosecond precision.
    Logs performance metrics.

    Args:
        func (Callable): The function to time.

    Returns:
        Callable: The wrapped function.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.perf_counter_ns()
        is_async = asyncio.iscoroutinefunction(func)
        try:
            return await func(*args, **kwargs) if is_async else func(*args, **kwargs)
        finally:
            duration = (time.perf_counter_ns() - start) / 1e6
            log_event(
                f"PERF: {func.__name__} took {duration:.3f}ms",
                metadata={"function": func.__name__, "duration_ms": duration}
            )

    return wrapper

def validate_input_text(text: str) -> str:
    """
    Hardened input sanitization pipeline.

    This function removes control characters and multiple spaces,
    and it also utilizes the centralized sanitize_input_text for further processing.

    Args:
        text (str): Raw input text.

    Returns:
        str: Sanitized text.
    """
    if not isinstance(text, str):
        return ""
    # Remove control characters except basic whitespace
    text = ''.join(c for c in text if ord(c) >= 32 or c in {'\t', '\n', '\r'})
    text = sanitize_input_text(text)
    return ' '.join(text.strip().split())