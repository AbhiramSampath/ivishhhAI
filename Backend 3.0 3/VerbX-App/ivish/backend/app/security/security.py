"""
Security utilities stub
"""

def sanitize_collection_name(name: str) -> str:
    """Stub function to sanitize collection name"""
    return name.replace(".", "_").replace("$", "_")

def prove_db_access(pid: int) -> bool:
    """Stub function for ZKP DB access proof"""
    return True

def validate_key_name(key: str) -> bool:
    """Stub function to validate Redis key name"""
    return len(key) > 0 and not any(char in key for char in ['\n', '\r', '\0'])

def sanitize_redis_value(value: str) -> str:
    """Stub function to sanitize Redis value"""
    return value.replace('\n', '').replace('\r', '').replace('\0', '')
