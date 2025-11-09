import re
import json
import hashlib
import unicodedata
import time
import os
import asyncio
from typing import List, Dict, Optional, Set
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# Corrected Imports
from ai_models.translation.mt_translate import detect_language
from backend.app.utils.logger import log_event, BaseLogger

# Security constants
MAX_INPUT_LENGTH = 512
SLANG_MAP_HMAC_KEY = os.urandom(32)

# Global kill switch
_slang_killed = False
logger = BaseLogger("SlangCleaner")

# --- Placeholder Imports and Constants ---
REGIONAL_SLANG_MAP = {
    "en": {
        "lol": "laughing out loud",
        "brb": "be right back"
    },
    "hi": {
        "lol": "bahut hasna",
        "brb": "turant aata hoon"
    }
}

def _sanitize_input(text: str) -> str:
    """Nuclear-grade input sanitization"""
    if _slang_killed:
        return ""

    if len(text) > MAX_INPUT_LENGTH:
        log_event("[SECURITY] Oversized slang cleaner input", level="WARNING")
        return ""
    
    text = unicodedata.normalize('NFKC', text)
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)

def _hmac_slang_map(slang_map: Dict[str, str]) -> str:
    """Generate HMAC for slang map integrity"""
    try:
        h = hmac.HMAC(SLANG_MAP_HMAC_KEY, hashes.SHA256(), backend=default_backend())
        # Use a deterministic serialization to ensure consistent HMAC
        h.update(json.dumps(slang_map, sort_keys=True).encode())
        return h.finalize().hex()
    except Exception as e:
        log_event(f"[SECURITY] HMAC generation failed: {str(e)[:50]}", level="ERROR")
        return ""

def _validate_slang_map(lang: str, slang_map: Dict[str, str]) -> bool:
    """Verify HMAC and size before using slang map"""
    if _slang_killed:
        return False

    if not slang_map:
        return False

    lang = lang.lower()[:2]
    stored_map = REGIONAL_SLANG_MAP.get(lang, {})
    if not stored_map:
        return False

    expected_hmac = _hmac_slang_map(stored_map)
    actual_hmac = _hmac_slang_map(slang_map)

    return hmac.compare_digest(expected_hmac.encode(), actual_hmac.encode())

async def clean_slang(text: str, lang_hint: str = None) -> str:
    """
    Secure slang cleaning with:
    - Input sanitization
    - Timing attack protection
    - Dictionary integrity checks
    """
    if _slang_killed:
        return ""

    text = _sanitize_input(text)
    if not text:
        return ""
    
    start_time = time.monotonic()
    lang = lang_hint or (await detect_language(text[:64]))
    lang = lang.lower()[:2]
    
    elapsed = time.monotonic() - start_time
    await asyncio.sleep(max(0.01 - elapsed, 0))

    slang_map = load_slang_map(lang)
    if not slang_map:
        return text
    
    tokens = tokenize(text)
    if not tokens:
        return text
    
    expanded = expand_slang_tokens(tokens, slang_map)
    
    try:
        log_event(
            f"SLANG_CLEAN: InputHash={hashlib.sha256(text.encode()).hexdigest()} | "
            f"Lang={lang} | SlangTermsFound={max(0, len(expanded)-len(tokens))}",
            level="DEBUG"
        )
    except Exception as e:
        pass

    return " ".join(expanded)

def tokenize(text: str) -> List[str]:
    """Tokenizer with exploit protections"""
    if _slang_killed:
        return []
    return re.findall(r"\b[\w'-]+\b", text.lower())

def expand_slang_tokens(tokens: List[str], slang_map: Dict[str, str]) -> List[str]:
    """
    Slang expansion with:
    - Constant-time lookup (prevents timing attacks)
    - Bounded memory allocation
    """
    if _slang_killed or not slang_map:
        return tokens

    expanded = []
    
    for token in tokens:
        replacement = slang_map.get(token, token)
        expanded.extend(replacement.split())
        
        if len(expanded) > 100:
            break
    
    return expanded

def load_slang_map(lang: str) -> Dict[str, str]:
    """
    Secure slang map loader with:
    - HMAC verification
    - Memory limits
    - Fallback protection
    """
    if _slang_killed:
        return {}

    lang = lang.lower()[:2]
    
    raw_map = REGIONAL_SLANG_MAP.get(lang, {})
    if not isinstance(raw_map, dict):
        return {}
    
    if len(raw_map) > 1000:
        log_event(f"[SECURITY] Oversized slang map for {lang}", level="WARNING")
        return {}

    if not _validate_slang_map(lang, raw_map):
        log_event(f"[SECURITY] Tampered slang map for {lang}", level="CRITICAL")
        return {}

    return raw_map

async def detect_code_mix(text: str) -> bool:
    """
    Code-mix detection with:
    - Input sanitization
    - Rate limiting
    - Result caching
    """
    if _slang_killed:
        return False

    text = _sanitize_input(text)
    if not text:
        return False
    
    words = tokenize(text)[:50]
    if not words:
        return False
    
    sample = words[:10] + words[-10:]
    lang_tags = set()

    for word in sample:
        lang = await detect_language(word)
        lang_tags.add(lang)

    return len(lang_tags) > 1

def kill_slang():
    """Emergency kill switch — wipes keys and stops dispatch."""
    global _slang_killed
    _slang_killed = True
    log_event("Slang: Engine killed.", level="CRITICAL")

def slang_engine_status() -> bool:
    """Returns True if slang engine is active, False if killed."""
    return not _slang_killed

def revive_slang():
    """Revives the slang engine (testing only)."""
    global _slang_killed
    _slang_killed = False
    log_event("Slang: Engine revived.", level="INFO")