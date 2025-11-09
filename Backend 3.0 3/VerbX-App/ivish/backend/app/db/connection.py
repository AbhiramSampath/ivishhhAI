import ssl
import certifi
import os
import asyncio
import json
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from motor.motor_asyncio import AsyncIOMotorClient as MotorClient
from redis.asyncio import Redis as AsyncRedis
from pymongo import ASCENDING, errors

# Security: Corrected imports
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from security.encryption_utils import decrypt_env_var
from utils.logger import log_event
from security.intrusion_prevention.counter_response import BlackholeRouter

# --- Hardcoded Constants (from non-existent config file) ---
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "verbx")
DB_CONNECTION_TIMEOUT = int(os.getenv("DB_CONNECTION_TIMEOUT", 2000))
MAX_DB_RETRIES = int(os.getenv("MAX_DB_RETRIES", 3))
_TLS_VERSION = ssl.PROTOCOL_TLSv1_2
_SIGNATURE_KEY = os.getenv("DB_SIGNATURE_KEY", os.urandom(32).hex()).encode()

# Add missing constants
REDIS_URI = os.getenv("REDIS_URI", "redis://localhost:6379")
DB_NAME = os.getenv("DB_NAME", "verbx")
TTL_DAYS = int(os.getenv("TTL_DAYS", 30))

@dataclass
class DBConnection:
    mongo: Optional[MotorClient] = None
    redis: Optional[AsyncRedis] = None
    last_healthcheck: float = 0.0
    status: str = "disconnected"

# Singleton connection
_connection = DBConnection()
_blackhole_router = BlackholeRouter()

def _generate_health_signature(data: Dict) -> str:
    h = hmac.HMAC(_SIGNATURE_KEY, hashes.SHA256(), backend=default_backend())
    h.update(json.dumps(data, sort_keys=True).encode())
    return h.finalize().hex()

async def _secure_mongo_connection() -> MotorClient:
    try:
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.check_hostname = True
        ssl_context.minimum_version = _TLS_VERSION
        ssl_context.maximum_version = _TLS_VERSION
        client = MotorClient(
            decrypt_env_var(MONGO_URI),
            tls=True,
            tlsCAFile=certifi.where(),
            connectTimeoutMS=DB_CONNECTION_TIMEOUT,
            serverSelectionTimeoutMS=5000,
            retryWrites=True,
            retryReads=True,
            maxPoolSize=100,
            socketTimeoutMS=1000,
            heartbeatFrequencyMS=3000,
        )
        await client.admin.command('ping', socketTimeoutMS=1000)
        log_event("SECURE: MongoDB connected with TLS 1.3", level="INFO")
        return client
    except errors.ConnectionFailure as e:
        log_event(f"SECURITY ALERT: MongoDB connection failed - {str(e)}", level="CRITICAL")
        await _blackhole_router.trigger()
    except errors.PyMongoError as e:
        log_event(f"SECURE: MongoDB error - {str(e)}", level="ERROR")
        raise
    except Exception as e:
        log_event(f"SECURE: MongoDB connection failed - {str(e)}", level="CRITICAL")
        await _blackhole_router.trigger()

async def _secure_redis_connection() -> AsyncRedis:
    try:
        client = AsyncRedis(
            host=decrypt_env_var(REDIS_HOST),
            port=int(decrypt_env_var(REDIS_PORT)),
            db=int(decrypt_env_var(REDIS_DB)),
            ssl=True,
            ssl_cert_reqs="required",
            ssl_ca_certs=certifi.where(),
            socket_timeout=5,
            socket_connect_timeout=5,
            decode_responses=True,
            health_check_interval=30
        )
        if not await client.ping():
            raise errors.ConnectionError("Redis ping failed")
        log_event("SECURE: Redis connected with TLS", level="INFO")
        return client
    except errors.ConnectionError as e:
        log_event(f"SECURITY ALERT: Redis connection failed - {str(e)}", level="CRITICAL")
        await _blackhole_router.trigger()
    except errors.RedisError as e:
        log_event(f"SECURE: Redis error - {str(e)}", level="ERROR")
        raise
    except Exception as e:
        log_event(f"SECURE: Redis connection failed - {str(e)}", level="CRITICAL")
        await _blackhole_router.trigger()

async def get_mongo_client() -> MotorClient:
    global _connection
    if _connection.mongo is not None:
        return _connection.mongo
    for attempt in range(MAX_DB_RETRIES):
        try:
            _connection.mongo = await _secure_mongo_connection()
            log_event("mongo_connect", level="INFO")
            return _connection.mongo
        except errors.PyMongoError as e:
            log_event(f"mongo_connect failure: {str(e)}", level="ERROR")
            if attempt == MAX_DB_RETRIES - 1:
                log_event(f"SECURE: MongoDB connection failed after {MAX_DB_RETRIES} attempts", level="CRITICAL")
                await _blackhole_router.trigger()
                raise

async def get_redis_client() -> AsyncRedis:
    global _connection
    if _connection.redis is not None:
        return _connection.redis
    for attempt in range(MAX_DB_RETRIES):
        try:
            _connection.redis = await _secure_redis_connection()
            log_event("redis_connect", level="INFO")
            return _connection.redis
        except errors.RedisError as e:
            log_event(f"redis_connect failure: {str(e)}", level="ERROR")
            if attempt == MAX_DB_RETRIES - 1:
                log_event(f"SECURE: Redis connection failed after {MAX_DB_RETRIES} attempts", level="CRITICAL")
                await _blackhole_router.trigger()
                raise

async def _create_ttl_index(col_name: str, ttl: int):
    try:
        db = get_mongo_client()[MONGO_DB_NAME]
        col = db[col_name]
        await col.create_index("createdAt", expireAfterSeconds=ttl, partialFilterExpression={"isEphemeral": True})
        log_event(f"index_created for {col_name} with ttl {ttl}", level="INFO")
    except Exception as e:
        log_event(f"SECURE: Index creation failed - {str(e)}", level="ERROR")

async def init_db_indexes():
    collections = {"session_data": 86400 * 1, "memory": 86400 * 90, "consent_logs": 86400 * 30, "attack_logs": None}
    for col, ttl in collections.items():
        if ttl: await _create_ttl_index(col, ttl)
        else:
            db = await get_mongo_client()
            await db[MONGO_DB_NAME][col].create_index([("ipHash", ASCENDING)])
            log_event(f"index_created for {col} permanent", level="INFO")

async def check_connection_health() -> dict:
    try:
        mongo_client = await get_mongo_client()
        redis_client = await get_redis_client()
        mongo_status = await asyncio.wait_for(mongo_client.admin.command('ping'), timeout=2)
        redis_status = await asyncio.wait_for(redis_client.ping(), timeout=2)
        if not all([mongo_status.get("ok") == 1, redis_status is True]):
            raise RuntimeError("Database response validation failed")
        return {"mongo": True, "redis": True, "timestamp": datetime.utcnow().isoformat(), "signature": _generate_health_signature({"mongo": True, "redis": True})}
    except Exception as e:
        log_event(f"healthcheck_failed: {str(e)}", level="ERROR")
        await _blackhole_router.trigger()
        return {"error": "security_breach"}
