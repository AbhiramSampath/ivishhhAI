import os
import time
import uuid
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from dataclasses import dataclass
from functools import partial
import asyncio
import hmac
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
# 🔐 Security Imports - CORRECTED PATHS
from db.connection import MONGO_URI, REDIS_URI, DB_NAME, TTL_DAYS
from utils.logger import log_event
from security.zkp_handler import prove_db_access, ZKPAuthenticator
from security.security import sanitize_collection_name
from security.blockchain.blockchain_utils import BlockchainDBLogger
# from ..security.intrusion_prevention.counter_response import BlackholeRouter
class BlackholeRouter:
    async def trigger(self):
        pass
from motor.motor_asyncio import AsyncIOMotorClient as MotorClient
from redis.asyncio import Redis as AsyncRedis
import pymongo

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("DB_INIT_HMAC_KEY", os.urandom(32).hex()).encode()
_SALT = os.urandom(16)
_KDF_ITERATIONS = 100000
_LATENCY_BUDGET_MS = 150
_MAX_RETRIES = 3
_MAX_MEMORY_MB = 500
_SUPPORTED_MONGO_VERSION = os.getenv("MONGO_VERSION", "6.0")
_SUPPORTED_REDIS_VERSION = os.getenv("REDIS_VERSION", "7.0")
_START_TIME = datetime.utcnow()

@dataclass
class DBFingerprint:
    db_type: str
    process: str
    version: str
    timestamp: str
    hash: str

class SecureDBInitializer:
    def __init__(self):
        self.mongo_client = None
        self.redis_client = None
        self.db = None
        self._fingerprint = None
        self.blockchain_logger = BlockchainDBLogger()
        self.blackhole_router = BlackholeRouter()
        self.zkp_auth = ZKPAuthenticator()

    async def _sign_result(self, result: Dict) -> str:
        h = hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        h.update(json.dumps(result, sort_keys=True).encode())
        return h.finalize().hex()

    def _generate_nonce(self) -> str:
        return os.urandom(16).hex()

    async def _init_mongo(self):
        try:
            if not await prove_db_access(os.getpid()):
                raise RuntimeError("ZKP DB access verification failed")

            self.mongo_client = MotorClient(
                MONGO_URI,
                serverSelectionTimeoutMS=5000,
                tls=True,
                tlsAllowInvalidCertificates=False,
                retryWrites=False,
                connectTimeoutMS=2000,
                socketTimeoutMS=2000,
                appname="ivish_core"
            )
            admin_db = self.mongo_client.admin
            server_status = await admin_db.command('serverStatus')
            if server_status["version"] < _SUPPORTED_MONGO_VERSION:
                raise RuntimeError("MongoDB version not supported")

            self._fingerprint = DBFingerprint(
                db_type="mongodb", process=server_status["process"], version=server_status["version"],
                timestamp=datetime.now().isoformat(), hash=self._compute_db_hash(str(server_status["process"]).encode())
            )
            self.db = self.mongo_client[DB_NAME]
            ttl_collections = {"session_data": {"field": "createdAt", "ttl": TTL_DAYS * 86400}, "temp_memory": {"field": "createdAt", "ttl": TTL_DAYS * 86400}, "emotion_logs": {"field": "timestamp", "ttl": TTL_DAYS * 86400}}
            for col_name, config in ttl_collections.items():
                sanitized_col = sanitize_collection_name(col_name)
                if not sanitized_col: continue
                await self.db[sanitized_col].create_index([(config["field"], pymongo.ASCENDING)], expireAfterSeconds=config["ttl"], partialFilterExpression={"allowTTL": True})
            await self.db.create_collection("audit_trail", capped=True, size=1e7)
            log_event("MongoDB initialized with security hardening.")
        except Exception as e:
            await self._handle_db_failure(e, "mongodb")
            raise

    async def _init_redis(self):
        try:
            self.redis_client = AsyncRedis.from_url(REDIS_URI, decode_responses=False, socket_timeout=2, socket_keepalive=True, health_check_interval=10, max_connections=100, ssl=True, ssl_cert_reqs='required')
            await self.redis_client.config_set('maxmemory-policy', 'volatile-lru')
            await self.redis_client.config_set('maxmemory', f'{_MAX_MEMORY_MB}mb')
            test_key = f"ivish:test:{self._generate_nonce()}"
            await self.redis_client.setex(test_key, timedelta(seconds=1), b"1")
            await self.redis_client.get(test_key)
            log_event("Redis connected with security policies.")
        except Exception as e:
            await self._handle_db_failure(e, "redis")
            raise

    def _compute_db_hash(self, data: bytes) -> str:
        digest = hashlib.sha256()
        digest.update(data)
        return digest.hexdigest()

    async def _handle_db_failure(self, error: Exception, db_type: str):
        log_event(f"DB_FAILURE: {str(error)}", level="CRITICAL")
        await self.blockchain_logger.log_db_failure(db_type, str(error))
        if self.mongo_client: self.mongo_client.close()
        if self.redis_client: await self.redis_client.close()
        await self.blackhole_router.trigger()

    async def get_db_handles(self) -> Dict[str, Any]:
        if not await self.verify_connections():
            raise RuntimeError("Database connections compromised")
        return {"mongo": self.db, "redis": self.redis_client}

    async def verify_connections(self) -> bool:
        try:
            mongo_status = await self.mongo_client.admin.command('ping')
            if not mongo_status.get('ok') == 1.0: return False
            if not await self.redis_client.ping(): return False
            admin_db = self.mongo_client.admin
            server_status = await admin_db.command('serverStatus')
            current_hash = self._compute_db_hash(str(server_status['process']).encode())
            if current_hash != self._fingerprint.hash:
                log_event("DB_TAMPER_DETECTED", level="ALERT"); return False
            return True
        except Exception as e:
            log_event(f"CONNECTION_VERIFY_FAILURE: {str(e)}"); return False

def get_start_time() -> datetime: return _START_TIME

db_initializer = SecureDBInitializer()

async def get_mongo_client() -> MotorClient:
    if not db_initializer.mongo_client: await db_initializer._init_mongo()
    return db_initializer.mongo_client

async def get_redis_client() -> AsyncRedis:
    if not db_initializer.redis_client: await db_initializer._init_redis()
    return db_initializer.redis_client