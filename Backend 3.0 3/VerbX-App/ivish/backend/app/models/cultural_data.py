# backend/models/cultural_data.py
# 🔒 Nuclear-Grade Cultural Date Engine with Zero-Trust Validation

import os
import time
import uuid
import hashlib
import logging
import asyncio
import json
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List, Union
from dataclasses import dataclass
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

# Internal imports - CORRECTED PATHS
from utils.logger import log_event
from utils.lang_codes import get_calendar_format, validate_locale
from security.blockchain.zkp_handler import validate_date_access
from security.blockchain.blockchain_utils import log_date_event
from security.intrusion_prevention.counter_response import BlackholeRouter
from middlewares.rate_limiter import RateLimiter

# External libraries (assumed to be installed)
import dateparser
import babel.dates
from hijri_converter import convert
from indian_calendar import convert_to_saka

# Security constants
MAX_DATE_RANGE = 365 * 10
SUPPORTED_CALENDARS = {"gregorian", "hijri", "buddhist", "persian", "hebrew", "julian", "indian"}
MAX_DATE_RATE = int(os.getenv("MAX_DATE_RATE", 20))
BLACKHOLE_DELAY = int(os.getenv("BLACKHOLE_DELAY", 60))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", 60))
TEMP_DATE_PATHS = ["/tmp/ivish_date_*", "/dev/shm/date_*"]
DATE_AES_KEY = os.getenv("DATE_AES_KEY", os.urandom(32)).encode()
if len(DATE_AES_KEY) != 32:
    log_event("CRITICAL: Invalid encryption key for cultural_date", alert=True)

logger = logging.getLogger(__name__)
rate_limiter = RateLimiter()
blackhole_router = BlackholeRouter()

@dataclass
class CulturalDate:
    date: datetime
    formatted: str
    calendar: str
    is_sensitive: bool
    metadata: Dict[str, Any]
    integrity_hash: str = ""

    def __post_init__(self):
        self.integrity_hash = self._compute_integrity_hash()

    def _compute_integrity_hash(self) -> str:
        data_to_hash = {k: v for k, v in self.__dict__.items() if k != "integrity_hash"}
        h = HMAC(DATE_AES_KEY, hashes.SHA256(), backend=default_backend())
        h.update(json.dumps(data_to_hash, sort_keys=True).encode())
        return h.finalize().hex()

class NuclearDateEngine:
    def __init__(self):
        self._festival_data = self._load_festival_map()

    async def _validate_rate_limit(self, user_id: str) -> bool:
        is_limited = not await rate_limiter.check_limit(user_id, rate=MAX_DATE_RATE, window=RATE_LIMIT_WINDOW)
        if is_limited:
            log_event("[SECURITY] Date rate limit exceeded", alert=True)
            await blackhole_router.trigger(delay_sec=BLACKHOLE_DELAY)
        return not is_limited

    @lru_cache(maxsize=1000)
    async def parse_natural_date(self, text: str, lang: str = "en", user_id: str = "", zk_proof: str = "") -> Dict[str, Any]:
        if not await self._validate_rate_limit(user_id):
            return {"status": "rate_limited", "error": "Too many requests"}

        if user_id and not await validate_date_access(user_id, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}

        if not text or len(text) > 100:
            return {"status": "invalid", "error": "Empty or oversized input"}

        try:
            dt = await asyncio.to_thread(
                dateparser.parse,
                text,
                languages=[lang[:2]],
                settings={'PREFER_DATES_FROM': 'future', 'RELATIVE_BASE': datetime.now(), 'MAX_DATE_RANGE': MAX_DATE_RANGE}
            )
            if not dt or dt.year > 2100:
                raise ValueError("Invalid date range")

            await log_date_event({"action": "parse_natural_date", "text": text, "lang": lang, "timestamp": time.time()})

            return {"status": "success", "date": dt, "calendar": "gregorian", "source_text": text, "integrity": CulturalDate(date=dt, formatted="", calendar="gregorian", is_sensitive=False, metadata={})._compute_integrity_hash()}
        except Exception as e:
            log_event(f"[DATE] Parse failed: {str(e)}", alert=True)
            return {"status": "failed", "error": str(e)}

    @lru_cache(maxsize=1000)
    async def format_cultural_date(self, dt: datetime, locale: str = "en_IN", calendar: str = "gregorian", user_id: str = "", zk_proof: str = "") -> Dict[str, Any]:
        if not await self._validate_rate_limit(user_id):
            return {"status": "rate_limited", "error": "Too many requests"}
        if user_id and not await validate_date_access(user_id, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}
        if not await asyncio.to_thread(validate_locale, locale) or calendar not in SUPPORTED_CALENDARS:
            return {"status": "invalid", "error": "Unsupported locale or calendar"}

        try:
            if calendar != "gregorian":
                converted = await asyncio.to_thread(self._convert_calendar, dt, calendar)
                formatted = converted["formatted"]
            else:
                formatted = await asyncio.to_thread(babel.dates.format_datetime, dt, format="full", locale=locale, calendar=calendar)

            metadata = self._get_region_metadata(dt, locale[:2])
            is_sensitive = metadata.get("avoid_meeting", False)

            await log_date_event({"action": "format_cultural_date", "date": dt.isoformat(), "locale": locale, "calendar": calendar, "is_sensitive": is_sensitive})

            return {"status": "success", "date": dt, "formatted": formatted, "calendar": calendar, "is_sensitive": is_sensitive, "metadata": metadata, "integrity": CulturalDate(date=dt, formatted=formatted, calendar=calendar, is_sensitive=is_sensitive, metadata=metadata)._compute_integrity_hash()}
        except Exception as e:
            log_event(f"[DATE] Format failed: {str(e)}", alert=True)
            return {"status": "failed", "error": str(e)}

    def _convert_calendar(self, dt: datetime, target_calendar: str) -> Dict[str, Any]:
        if target_calendar == "hijri":
            hijri = convert.Gregorian(dt.year, dt.month, dt.day).to_hijri()
            return {"date": dt, "calendar": target_calendar, "converted": hijri, "formatted": f"{hijri.day} {hijri.month_name()} {hijri.year} (Hijri)", "integrity": CulturalDate(date=dt, formatted="", calendar=target_calendar, is_sensitive=False, metadata={"converted": hijri})._compute_integrity_hash()}
        elif target_calendar == "buddhist":
            return {"date": dt, "calendar": target_calendar, "converted": datetime(dt.year + 543, dt.month, dt.day), "formatted": f"{dt.day} {dt.strftime('%B')} {dt.year + 543} (B.E.)"}
        elif target_calendar == "indian":
            saka = convert_to_saka(dt.year, dt.month, dt.day)
            return {"date": dt, "calendar": target_calendar, "converted": saka, "formatted": f"{saka.day} {saka.month_name()} {saka.year} (Saka Era)", "integrity": CulturalDate(date=dt, formatted="", calendar=target_calendar, is_sensitive=False, metadata={"converted": saka})._compute_integrity_hash()}
        else:
            return {"date": dt, "calendar": "gregorian", "converted": dt, "formatted": dt.strftime("%d %B %Y"), "integrity": CulturalDate(date=dt, formatted="", calendar="gregorian", is_sensitive=False, metadata={"converted": dt})._compute_integrity_hash()}

    async def get_cultural_context(self, dt: datetime, region: str = "IN", user_id: str = "", zk_proof: str = "") -> Dict[str, Any]:
        if user_id and not await validate_date_access(user_id, zk_proof):
            return {"status": "unauthorized", "error": "Access denied"}
        try:
            locale = f"en_{region}"
            calendar = get_calendar_format(region)
            formatted = await self.format_cultural_date(dt, locale, calendar, user_id, zk_proof)
            metadata = self._get_region_metadata(dt, region)
            return {"date": dt, "formatted": formatted["formatted"], "calendar": calendar, "is_sensitive": metadata["avoid_meeting"], "metadata": metadata, "region": region, "timestamp": time.time()}
        except Exception as e:
            log_event(f"[DATE] Context retrieval failed: {str(e)}", alert=True)
            return {"status": "failed", "error": str(e)}

    def _load_festival_map(self) -> Dict:
        return {"IN": {"10-24": {"name": "Dussehra", "avoid_meeting": True}, "01-26": {"name": "Republic Day", "avoid_meeting": False}}, "SA": {"12-10": {"name": "Eid al-Fitr", "avoid_meeting": True}}}

    def _get_region_metadata(self, dt: datetime, region: str) -> Dict:
        key = f"{dt.month:02}-{dt.day:02}"
        return self._festival_data.get(region, {}).get(key, {"name": None, "avoid_meeting": False})

date_engine = NuclearDateEngine()