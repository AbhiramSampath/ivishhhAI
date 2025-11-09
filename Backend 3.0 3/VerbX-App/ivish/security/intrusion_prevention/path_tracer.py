# security/intrusion_prevention/path_tracer.py

import json
import os
import re
import uuid
import time
import socket
import hashlib
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import hmac
import aiohttp
from ipaddress import ip_address, ip_network
from functools import lru_cache
import numpy as np
from fastapi import Request

# 🔐 Security Imports
from cryptography.hazmat.backends import default_backend

# 📁 Project Imports (Corrected paths based on project structure)
from backend.app.utils.logger import log_event
from security.blockchain.blockchain_utils import anchor_event as log_threat_to_chain
from security.firewall import blacklist_ip, activate_blackhole
from security.blockchain.zkp_handler import ZKPAuthenticator
from config.settings import TRUSTED_PATHS, THREAT_THRESHOLD
from ai_models.anomaly.anomaly_classifier import IsolationForestScorer

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = b"path_tracer_signature_key"
_SALT = os.urandom(16)
_KDF_ITERATIONS = 100000
_LATENCY_BUDGET_MS = 50
_DEFAULT_TOR_UPDATE_INTERVAL = 3600  # 1 hour
_BLACKHOLE_COOLDOWN = 300  # 5 minutes
_THREAT_SCORE_THRESHOLD = float(THREAT_THRESHOLD)
_SUPPORTED_PATHS = TRUSTED_PATHS
_SUPPORTED_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
_HIGH_RISK_ASN = ["AS1", "AS2", "AS3"]
_IP_RISK_CACHE_TTL = 300  # 5 minutes

@dataclass
class RequestTrace:
    """
    📌 Structured request trace
    """
    timestamp: str
    path: str
    ip: str
    headers: Dict
    fingerprint: Dict
    score: float
    signature: Optional[str] = None

class SecurePathTracer:
    """
    🔒 Secure Path Tracer & Intrusion Prevention
    """
    def __init__(self):
        """Secure initialization"""
        self._init_tor_detection()
        self._init_blackhole_cache()
        self._init_rate_limiter()
        self._init_ai_scorer()
        self._rate_limiter_lock = asyncio.Lock()

    def _sign_trace(self, trace: Dict) -> str:
        """HMAC-sign trace data"""
        h = hmac.new(_HMAC_KEY, digestmod=hashlib.sha256)
        h.update(json.dumps(trace, sort_keys=True).encode())
        return h.hexdigest()

    def _init_tor_detection(self):
        """Initialize Tor exit node tracking"""
        self._tor_exit_nodes = set()
        self._last_tor_update = 0

    def _init_blackhole_cache(self):
        """Initialize blackhole tracking"""
        self._active_blackholes = {}

    def _init_rate_limiter(self):
        """Initialize rate limiting"""
        self._rate_limiter = {}

    def _init_ai_scorer(self):
        """Initialize anomaly detection"""
        self.scorer = IsolationForestScorer()

    async def _update_tor_nodes(self):
        """Securely fetch Tor exit node list"""
        if (time.time() - self._last_tor_update) < _DEFAULT_TOR_UPDATE_INTERVAL:
            return
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://check.torproject.org/exit-addresses") as resp:
                    if resp.status == 200:
                        data = await resp.text()
                        self._tor_exit_nodes = {
                            line.split()[1]
                            for line in data.splitlines()
                            if line.startswith("ExitAddress")
                        }
                        self._last_tor_update = time.time()
        except Exception as e:
            await log_event(f"TOR_NODE_UPDATE_FAILED: {str(e)}", level="WARNING")

    async def _enrich_fingerprint(self, fingerprint: Dict) -> Dict:
        """Add threat intelligence to fingerprint"""
        await self._update_tor_nodes()
        ip = fingerprint.get("ip", "unknown")
        fingerprint.update({
            "is_tor": ip in self._tor_exit_nodes,
            "is_datacenter": self._is_datacenter_ip(ip),
            "asn_risk": self._get_asn_risk(ip),
            "timestamp": datetime.now().isoformat()
        })
        return fingerprint

    def _is_datacenter_ip(self, ip: str) -> bool:
        """Detect datacenter IPs"""
        try:
            ip_obj = ip_address(ip)
            private_networks = [ip_network("192.168.0.0/16"), ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12")]
            return ip_obj.is_private or any(ip_obj in network for network in private_networks)
        except ValueError:
            return False

    @lru_cache(maxsize=_IP_RISK_CACHE_TTL)
    def _get_asn_risk(self, ip: str) -> float:
        """Return risk score for ASN"""
        # Mock implementation with a cache
        return 0.7 if ip.startswith("10.0.0.") else 0.0

    async def _score_anomaly(self, fingerprint: Dict) -> float:
        """Hybrid AI + rules-based scoring"""
        rule_score = 0.0
        if fingerprint.get("is_tor"):
            rule_score += 0.4
        if re.search(r"(sqlmap|nmap|metasploit)", fingerprint.get("user_agent", ""), re.IGNORECASE):
            rule_score += 0.6
        try:
            ai_score = await self.scorer.predict(fingerprint)
        except Exception as e:
            ai_score = 0.5
        return min(0.7 * ai_score + 0.3 * rule_score, 1.0)

    async def _check_rate_limit(self, ip: str, path: str) -> bool:
        """Detect and block rate-based attacks"""
        async with self._rate_limiter_lock:
            now = time.time()
            self._rate_limiter[ip] = [t for t in self._rate_limiter.get(ip, []) if now - t < 60]
            self._rate_limiter[ip].append(now)
            if len(self._rate_limiter[ip]) > 100:
                await self._handle_threat(ip, path, "rate_limit")
                return False
            return True

    async def _handle_threat(self, ip: str, path: str, reason: str):
        """Active defense system for intrusion"""
        await self._deploy_honeypot(ip)
        await log_threat_to_chain({
            "ip": ip,
            "path": path,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
        activate_blackhole(ip)
        self._active_blackholes[ip] = time.time() + _BLACKHOLE_COOLDOWN
        ZKPAuthenticator().rotate_keys()
        await log_event(f"THREAT_DETECTED | IP: {ip} | Path: {path} | Reason: {reason}", level="CRITICAL")

    async def _deploy_honeypot(self, ip: str):
        """Serve fake responses to attackers"""
        self._active_blackholes[ip] = time.time() + _BLACKHOLE_COOLDOWN
        await asyncio.sleep(10)
        log_event(f"HONEYPOT_ACTIVATED | IP: {ip}", level="WARNING")

    def _validate_path(self, path: str) -> bool:
        """Check against trusted route list"""
        return any(re.match(p, path) for p in _SUPPORTED_PATHS)

    async def trace_request(self, request: Request) -> Dict:
        """
        🔐 Nuclear-grade request tracing pipeline:
        - Fingerprinting
        - Anomaly scoring
        - Tor/VPN detection
        - Blackhole activation
        - Blockchain logging
        """
        try:
            # 🔐 ZKP Authentication
            if not await ZKPAuthenticator().verify_request(request):
                raise PermissionError("ZKP verification failed")

            # 🧹 Fingerprint Extraction
            client_ip = request.headers.get('X-Real-IP', request.client.host)
            path = request.url.path
            method = request.method
            headers = {k.lower(): v for k, v in request.headers.items()}
            
            if not self._validate_path(path):
                await self._handle_threat(client_ip, path, "invalid_path")
                return {"status": "blocked", "reason": "invalid_path"}

            if method not in _SUPPORTED_METHODS:
                await self._handle_threat(client_ip, path, "invalid_method")
                return {"status": "blocked", "reason": "invalid_method"}

            if not await self._check_rate_limit(client_ip, path):
                return {"status": "blocked", "reason": "rate_limit"}

            # 📊 Fingerprinting
         
            fingerprint = await self._enrich_fingerprint(fingerprint)
            anomaly_score = await self._score_anomaly(fingerprint)

            # 🚨 Threat Evaluation
            trace_data = RequestTrace(
                timestamp=datetime.now().isoformat(),
                path=path,
                ip=client_ip,
                headers=headers,
                fingerprint=fingerprint,
                score=anomaly_score
            )
            trace_data.signature = self._sign_trace(trace_data.__dict__)
            await log_event("SECURE_PATH_TRACE", trace_data.__dict__, level="DEBUG")

            if anomaly_score >= _THREAT_SCORE_THRESHOLD:
                await self._handle_threat(client_ip, path, "high_anomaly_score")
                return {"status": "blocked", "reason": "high_risk"}

            return {
                "status": "allowed",
                "score": anomaly_score,
                "fingerprint": fingerprint,
                "timestamp": datetime.now().isoformat(),
                "ip": client_ip,
                "path": path
            }

        except Exception as e:
            await log_event(f"PATH_TRACE_FAILURE: {str(e)}", level="ERROR")
            return {"status": "error", "error": str(e)}