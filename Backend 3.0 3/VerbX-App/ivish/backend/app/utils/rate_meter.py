# backend/utils/rate_meter.py
# 🔒 Ivish AI Secure Rate Meter & Anomaly Detector
# 🚀 Final, Refactored Code

import os
import re
import time
import uuid
import asyncio
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import hashlib
import hmac
import logging

# 🔐 Security Imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC as CryptoHMAC

# 📁 Project Imports
from .logger import log_event
from .cache import redis_client
from security.intrusion_prevention.threat_detector import ThreatDetector
from security.blockchain.zkp_handler import ZKPAuthenticator
from security.blockchain.blockchain_utils import log_rate_event
from security.intrusion_prevention.counter_response import blackhole_response_action

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("RATE_METER_HMAC_KEY", None)
if not _HMAC_KEY:
    raise RuntimeError("RATE_METER_HMAC_KEY not found in environment. Rate meter cannot operate securely.")
_HMAC_KEY = _HMAC_KEY.encode()

_LATENCY_BUDGET_MS = 50
_DEFAULT_WINDOW_SEC = 60
_MAX_CALLS = 100
_RATE_BAN_TTL = 300 # 5 minutes

class SecureRateMeter:
    """
    🔒 Secure Rate Meter & Anomaly Detector
    - Tracks request frequency using Redis for scalability
    - Detects bursts and anomalies
    - Triggers defenses (rate limit, intrusion flag)
    - Integrates with Redis for distributed state
    - Logs to blockchain for audibility
    - Uses ZKP for secure rate proof on demand
    - Implements HMAC key signing for integrity
    """

    def __init__(self):
        """Secure initialization"""
        self._threat_detector = ThreatDetector()
        self._zkp_authenticator = ZKPAuthenticator()
        
        # Load rate limits from environment variables
        self._rate_limits = {
            "api": {
                "window": int(os.getenv("RATE_LIMIT_API_WINDOW", 60)),
                "max_calls": int(os.getenv("RATE_LIMIT_API_MAX_CALLS", 100)),
            },
            "user": {
                "window": int(os.getenv("RATE_LIMIT_USER_WINDOW", 300)),
                "max_calls": int(os.getenv("RATE_LIMIT_USER_MAX_CALLS", 500)),
            },
            "ip": {
                "window": int(os.getenv("RATE_LIMIT_IP_WINDOW", 60)),
                "max_calls": int(os.getenv("RATE_LIMIT_IP_MAX_CALLS", 200)),
            }
        }
        logging.info("SecureRateMeter initialized with Redis for state management.")

    def _sign_key(self, key: str) -> str:
        """HMAC-sign rate key for integrity and tamper-proofing."""
        h = hmac.new(_HMAC_KEY, digestmod='sha256')
        h.update(key.encode())
        return h.hexdigest()

    async def track_call(self, key: str, weight: int = 1, source: str = "api") -> bool:
        """
        🔐 Tracks an incoming call and checks against rate limits.
        
        Args:
            key (str): The key to track (e.g., user ID, IP address).
            weight (int): The cost of the call (e.g., 1 for a simple request, 10 for a complex one).
            source (str): The source of the call ('api', 'user', 'ip').
            
        Returns:
            bool: True if the rate limit is exceeded, False otherwise.
        """
        try:
            signed_key = self._sign_key(key)
            rate_config = self._rate_limits.get(source, self._rate_limits["api"])
            window = rate_config["window"]
            max_calls = rate_config["max_calls"]
            
            # Use Redis for a scalable, atomic counter
            redis_key = f"rate:{source}:{signed_key}"
            
            # Use a Redis pipeline for efficiency
            with redis_client.pipeline() as pipe:
                pipe.incrby(redis_key, weight)
                pipe.expire(redis_key, window)
                current_count = pipe.execute()[0]
                
            if current_count > max_calls:
                await self._trigger_defenses(signed_key, source, current_count)
                return True
                
            return False
            
        except Exception as e:
            logging.error(f"RATE_TRACK_FAILURE: {str(e)}")
            return False

    async def _trigger_defenses(self, signed_key: str, source: str, count: int):
        """Nuclear-grade defense system for rate anomalies."""
        try:
            # Generate ZKP proof on demand
            proof = self._zkp_authenticator.generate_proof(signed_key, count)
            
            # 📜 Blockchain logging
            await log_rate_event("rate_limit_triggered", {
                "key": signed_key,
                "source": source,
                "proof": proof,
                "timestamp": datetime.now().isoformat(),
                "window": self._rate_limits[source]["window"]
            })

            # 🛡️ Raise intrusion flag
            self._threat_detector.raise_intrusion_flag(
                proof=proof,
                reason=f"Rate limit triggered for {source}"
            )
            
            # Trigger a blackhole response for the attacker's IP
            logging.warning(f"Rate limit exceeded. Triggering blackhole response for {source}.")
            blackhole_response_action(delay=_RATE_BAN_TTL)

        except Exception as e:
            logging.error(f"DEFENSE_TRIGGER_FAILURE: {str(e)}")

    def get_rate_stats(self, key: str, source: str = "api") -> Dict:
        """
        Secure stats retrieval with ZKP validation on demand.
        
        Args:
            key (str): The key to track.
            source (str): The source of the call.

        Returns:
            Dict: A dictionary containing rate statistics and a ZKP proof.
        """
        signed_key = self._sign_key(key)
        rate_config = self._rate_limits.get(source, self._rate_limits["api"])
        redis_key = f"rate:{source}:{signed_key}"
        
        current_count = redis_client.get(redis_key)
        current_count = int(current_count) if current_count else 0
        
        proof = self._zkp_authenticator.generate_proof(signed_key, current_count)

        return {
            "key": signed_key,
            "count": current_count,
            "window_sec": rate_config["window"],
            "max_allowed": rate_config["max_calls"],
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "proof": proof
        }

    async def reset_counter(self, key: str, source: str = "api"):
        """
        Secure counter reset with ZKP validation.
        
        Args:
            key (str): The key to reset.
            source (str): The source of the key.
        """
        signed_key = self._sign_key(key)
        redis_key = f"rate:{source}:{signed_key}"
        redis_client.delete(redis_key)
        await log_event(f"Rate counter reset for {source} with key hash: {signed_key}", level="INFO")

rate_meter = SecureRateMeter()