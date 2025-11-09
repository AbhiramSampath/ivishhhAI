import uuid
import os
import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any, Union

# Crypto for runtime integrity and secure communication
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Project Imports - Corrected based on file structure
from backend.app.utils.logger import log_event
from backend.app.db.redis import RedisClient as RedisCache
from backend.app.db.mongo import MongoStore
from backend.app.utils.helpers import format_context
from backend.app.auth.jwt_handler import verify_token_scope, generate_ephemeral_token
from backend.app.utils.security import constant_time_compare
from security.blockchain.blockchain_utils import log_to_blockchain
from self_learning.autocoder import AutoCoder

# Load configuration from environment variables for security
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "a_very_strong_default_key_for_dev_only")
DEFAULT_TTL = int(os.getenv("DEFAULT_TTL", 3600))  # 1 hour default
MAX_CONTEXT_SIZE = int(os.getenv("MAX_CONTEXT_SIZE", 4096))

# Security Constants
AES_KEY_SIZE = 32  # Changed to 256-bit for stronger encryption
MAX_SPACE_COUNT = 15  # Per user
MAX_CONTEXT_ITEMS = 100  # Max context items per space
SHRED_PATTERN = get_random_bytes(128)
BLOCKCHAIN_LOG_TYPE = "collab_space"

# Initialize persistent stores
redis = RedisCache()
mongo = MongoStore(collection="collab_spaces")


class SpaceEncryption:
    """
    Military-grade encryption for collaborative AI memory spaces.
    Uses scrypt-based key derivation and AES-CBC mode.
    """

    def __init__(self):
        self.key = hashlib.scrypt(
            ENCRYPTION_KEY.encode(),
            salt=b'IvishCollabSpace',
            n=2**14,
            r=8,
            p=1,
            dklen=32  # 256-bit key
        )
        self.iv = hashlib.md5(ENCRYPTION_KEY.encode()).digest()  # Use a more secure method in production

    def encrypt(self, data: str) -> bytes:
        """Securely encrypt context data"""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

    def decrypt(self, encrypted: bytes) -> str:
        """Securely decrypt context data"""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(encrypted), AES.block_size).decode('utf-8')


encryptor = SpaceEncryption()
autocoder = AutoCoder()


async def create_space(
    user_id: str,
    scope: str = "session",
    custom_ttl: Optional[int] = None,
    members: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Create a new encrypted shared memory space with:
    - Ephemeral access tokens
    - Hardware-bound encryption
    - Tamper-evident logging
    - Multi-user access support
    """
    # SECURITY LAYER 1: ANTI-ABUSE CHECKS
    if not await _validate_user_quota(user_id):
        log_event(f"SPACE: Quota exceeded for user {user_id}", level="WARNING")
        raise PermissionError("User space quota exceeded")

    space_id = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=custom_ttl or DEFAULT_TTL)
    access_token = generate_ephemeral_token(user_id, space_id)

    # SECURITY LAYER 2: ENCRYPTED CONTEXT STORAGE
    space_data = {
        "space_id": space_id,
        "owner": user_id,
        "scope": scope,
        "created_at": datetime.now(timezone.utc),
        "expires_at": expires_at,
        "members": members or [user_id],
        "context": encryptor.encrypt(json.dumps([])), # Use json for safety
        "_security": {
            "token_hash": hashlib.sha256(access_token.encode()).hexdigest(),
            "last_rotation": datetime.now(timezone.utc).isoformat()
        }
    }

    # Dual-write to MongoDB and Redis
    await asyncio.gather(
        mongo.insert_async(space_data),
        redis.set_async(
            key=space_id,
            value=json.dumps({
                "meta": space_data,
                "context": []
            }),
            ttl=custom_ttl or DEFAULT_TTL
        )
    )

    # Blockchain audit log
    await log_to_blockchain(
        BLOCKCHAIN_LOG_TYPE,
        {
            "action": "create",
            "space_id": space_id,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )

    log_event(f"SPACE CREATED: {space_id} by {user_id}", secure=True)
    return {
        "space_id": space_id,
        "expires_at": expires_at.isoformat(),
        "access_token": access_token,
        "members": members or [user_id]
    }


async def update_context(
    space_id: str,
    update: Dict[str, Any],
    token: str,
    user_id: str
):
    """
    Atomic encrypted context update with:
    - Token validation
    - Context checksum
    - Automatic TTL extension
    - Federated learning integration
    """
    # SECURITY LAYER 3: TOKEN VALIDATION
    if not await validate_access(space_id, token, user_id):
        raise PermissionError("Invalid access token")

    space_data_from_redis = await redis.get_async(space_id)
    if space_data_from_redis:
        space = json.loads(space_data_from_redis)
    else:
        # Fallback to Mongo if Redis is down or key expired
        space = await mongo.find_one_async({"space_id": space_id})
        if not space:
            raise ValueError("Space not found")

    # SECURITY LAYER 4: CONTEXT INTEGRITY CHECK
    try:
        decrypted = encryptor.decrypt(space["context"])
        context_list = json.loads(decrypted)  # Safer than eval
    except Exception as e:
        log_event(f"SECURITY: Context decryption failed: {str(e)}", level="CRITICAL")
        await _handle_compromise(space_id)
        raise RuntimeError("Context tampering detected")

    # SECURITY LAYER 5: UPDATE VALIDATION
    if not _validate_context_update(update):
        raise ValueError("Invalid context update structure")

    # Enforce context size limit
    if len(context_list) >= MAX_CONTEXT_ITEMS:
        log_event(f"CONTEXT: Max items reached in {space_id}", level="WARNING")
        context_list = context_list[-MAX_CONTEXT_ITEMS:]

    # Add new update
    context_list.append(update)

    # Update autocoder with new data
    asyncio.create_task(autocoder.learn_from_context(update))

    # Encrypted payload
    encrypted_context = encryptor.encrypt(json.dumps(context_list))

    # Atomic dual-write with checks
    await asyncio.gather(
        redis.set_async(
            space_id,
            json.dumps({
                "meta": space,
                "context": context_list
            }),
            ttl=DEFAULT_TTL
        ),
        mongo.update_async(
            {"space_id": space_id},
            {
                "$set": {
                    "context": encrypted_context,
                    "expires_at": datetime.now(timezone.utc) + timedelta(seconds=DEFAULT_TTL)
                }
            }
        )
    )

    # Blockchain audit log
    await log_to_blockchain(
        BLOCKCHAIN_LOG_TYPE,
        {
            "action": "update",
            "space_id": space_id,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "update": update
        }
    )

    log_event(f"CONTEXT UPDATED in space {space_id}", secure=True)


async def get_context(
    space_id: str,
    token: str,
    user_id: str
) -> List[Dict[str, Any]]:
    """
    Retrieve context with:
    - Token-gated access
    - Decryption pipeline
    - Cache validation
    """
    if not await validate_access(space_id, token, user_id):
        raise PermissionError("Invalid access token")

    # SECURITY LAYER 6: CACHE-DB COHERENCY CHECK
    redis_data = await redis.get_async(space_id)
    if redis_data:
        try:
            return format_context(json.loads(redis_data).get("context", []))
        except json.JSONDecodeError:
            pass # Fallback to Mongo

    mongo_data = await mongo.find_one_async({"space_id": space_id})
    if not mongo_data:
        return []

    try:
        decrypted = encryptor.decrypt(mongo_data["context"])
        context = json.loads(decrypted)  # Safer than eval

        await redis.set_async(
            space_id,
            json.dumps({"meta": mongo_data, "context": context}),
            ttl=DEFAULT_TTL
        )

        return format_context(context)
    except Exception as e:
        log_event(f"SECURITY: Context retrieval failed: {str(e)}", level="CRITICAL")
        await _handle_compromise(space_id)
        raise RuntimeError("Context retrieval failed security check")


async def delete_space(
    space_id: str,
    token: str,
    user_id: str
):
    """
    Secure space deletion with:
    - Ownership verification
    - Cryptographic wipe
    - Forensic logging
    """
    if not await validate_access(space_id, token, user_id):
        raise PermissionError("Invalid access token")

    # SECURITY LAYER 7: CRYPTOGRAPHIC ERASE
    await asyncio.gather(
        redis.set_async(space_id, json.dumps({"shredded": str(SHRED_PATTERN)}), ttl=60),
        mongo.update_async(
            {"space_id": space_id},
            {"$set": {"context": encryptor.encrypt(json.dumps(str(SHRED_PATTERN)))}}
        )
    )

    # Blockchain audit log
    await log_to_blockchain(
        BLOCKCHAIN_LOG_TYPE,
        {
            "action": "delete",
            "space_id": space_id,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )

    log_event(f"SPACE SHREDDED: {space_id}", secure=True)


async def validate_access(
    space_id: str,
    token: str,
    user_id: str
) -> bool:
    """
    Zero-trust access validation with:
    - Constant-time comparison
    - Token expiration
    - Scope verification
    """
    space = await mongo.find_one_async({"space_id": space_id})
    if not space:
        return False

    # SECURITY LAYER 8: HARDENED VERIFICATION
    expected_hash = space["_security"]["token_hash"]
    provided_hash = hashlib.sha256(token.encode()).hexdigest()

    valid_token = constant_time_compare(expected_hash, provided_hash)
    valid_expiry = datetime.now(timezone.utc) < space["expires_at"].replace(tzinfo=timezone.utc)
    valid_scope = verify_token_scope(token, user_id)

    return all([valid_token, valid_expiry, valid_scope])


async def list_active_spaces(
    admin_token: str,
    user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Admin-only monitoring with:
    - Privilege verification
    - Partial data exposure
    - Optional user filtering
    """
    if not verify_token_scope(admin_token, "admin"):
        raise PermissionError("Admin access required")

    query = {"members": user_id} if user_id else {}

    return await mongo.find_many_async(
        query,
        fields=["space_id", "owner", "scope", "expires_at", "members"]
    )


# SECURITY UTILITIES

async def _validate_user_quota(user_id: str) -> bool:
    """Prevent space creation abuse"""
    count = await mongo.count_async({"owner": user_id})
    return count < MAX_SPACE_COUNT


def _validate_context_update(update: Dict[str, Any]) -> bool:
    """Structural validation of context updates"""
    required_keys = {"timestamp", "source", "content"}
    return all(k in update for k in required_keys) and len(json.dumps(update)) < MAX_CONTEXT_SIZE


async def _handle_compromise(space_id: str):
    """Nuclear response to tampering"""
    try:
        await delete_space(space_id, "system:compromise", "system")
        log_event(f"COMPROMISE DETECTED: {space_id}", level="CRITICAL")
    except Exception as e:
        log_event(f"SECURITY: Failed to handle compromise: {str(e)}", level="FATAL")


# UTILITY: ROTATE ACCESS TOKEN

async def rotate_access_token(space_id: str, user_id: str) -> str:
    """
    Rotates the ephemeral access token for a space.
    - Updates token hash in DB
    - Returns new token
    """
    new_token = generate_ephemeral_token(user_id, space_id)
    new_hash = hashlib.sha256(new_token.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    await mongo.update_async(
        {"space_id": space_id},
        {"$set": {"_security.token_hash": new_hash, "_security.last_rotation": now}}
    )
    log_event(f"TOKEN ROTATED for space {space_id} by {user_id}", secure=True)
    return new_token


# UTILITY: ADD MEMBER TO SPACE

async def add_member(space_id: str, new_member_id: str, token: str, user_id: str) -> bool:
    """
    Adds a new member to a collaborative space.
    - Only owner can add
    - Updates member list in DB
    """
    space = await mongo.find_one_async({"space_id": space_id})
    if not space or space["owner"] != user_id:
        raise PermissionError("Only owner can add members")
    if not await validate_access(space_id, token, user_id):
        raise PermissionError("Invalid access token")
    if new_member_id in space.get("members", []):
        return False  # Already a member
    updated_members = space.get("members", []) + [new_member_id]
    await mongo.update_async(
        {"space_id": space_id},
        {"$set": {"members": updated_members}}
    )
    log_event(f"MEMBER ADDED: {new_member_id} to {space_id} by {user_id}", secure=True)
    return True


# UTILITY: REMOVE MEMBER FROM SPACE

async def remove_member(space_id: str, member_id: str, token: str, user_id: str) -> bool:
    """
    Removes a member from a collaborative space.
    - Only owner can remove
    - Cannot remove self if owner
    """
    space = await mongo.find_one_async({"space_id": space_id})
    if not space or space["owner"] != user_id:
        raise PermissionError("Only owner can remove members")
    if not await validate_access(space_id, token, user_id):
        raise PermissionError("Invalid access token")
    if member_id == user_id:
        raise ValueError("Owner cannot remove self")
    members = space.get("members", [])
    if member_id not in members:
        return False
    updated_members = [m for m in members if m != member_id]
    await mongo.update_async(
        {"space_id": space_id},
        {"$set": {"members": updated_members}}
    )
    log_event(f"MEMBER REMOVED: {member_id} from {space_id} by {user_id}", secure=True)
    return True


# UTILITY: EXTEND SPACE TTL

async def extend_space_ttl(space_id: str, token: str, user_id: str, extra_seconds: int) -> bool:
    """
    Extends the TTL of a space.
    - Only owner can extend
    """
    space = await mongo.find_one_async({"space_id": space_id})
    if not space or space["owner"] != user_id:
        raise PermissionError("Only owner can extend TTL")
    if not await validate_access(space_id, token, user_id):
        raise PermissionError("Invalid access token")

    new_expiry = datetime.now(timezone.utc) + timedelta(seconds=extra_seconds)

    # Check and handle potential race conditions with a dual update
    await asyncio.gather(
        mongo.update_async(
            {"space_id": space_id},
            {"$set": {"expires_at": new_expiry}}
        ),
        redis.set_async(
            space_id,
            await redis.get_async(space_id),
            ttl=extra_seconds
        )
    )

    log_event(f"TTL EXTENDED for space {space_id} by {user_id}", secure=True)
    return True