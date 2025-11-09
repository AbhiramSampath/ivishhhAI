import os

# Database settings
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
REDIS_URI = os.getenv("REDIS_URI", "redis://localhost:6379")
DB_NAME = os.getenv("DB_NAME", "ivish")
TTL_DAYS = int(os.getenv("TTL_DAYS", "30"))

# Security settings
AES_SECRET_KEY = os.getenv("AES_SECRET_KEY", "default_aes_key").encode()
RSA_PRIVATE_KEY_PATH = os.getenv("RSA_PRIVATE_KEY_PATH", "/tmp/private.pem")
RSA_PUBLIC_KEY_PATH = os.getenv("RSA_PUBLIC_KEY_PATH", "/tmp/public.pem")

# JWT settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default_jwt_secret")

# Rate limiting
RATE_LIMIT_THRESHOLD = int(os.getenv("RATE_LIMIT_THRESHOLD", "100"))

# AI settings
DEFAULT_LANGUAGES = ["en", "es", "fr"]
ANOMALY_SCORE_THRESHOLD = float(os.getenv("ANOMALY_SCORE_THRESHOLD", "0.7"))

# Voice settings
BIOMETRIC_THRESHOLD = float(os.getenv("BIOMETRIC_THRESHOLD", "0.8"))
MAX_BIOMETRIC_RETRIES = int(os.getenv("MAX_BIOMETRIC_RETRIES", "3"))

# Translation settings
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en")
LANG_DEFAULT = os.getenv("LANG_DEFAULT", "en")
TRANSLATE_ENABLED = os.getenv("TRANSLATE_ENABLED", "true").lower() == "true"

# Video settings
ENABLE_EMOTION_TAGGING = os.getenv("ENABLE_EMOTION_TAGGING", "true").lower() == "true"
DEFAULT_SUB_LANG = os.getenv("DEFAULT_SUB_LANG", "en")
ENABLE_TTS_OUTPUT = os.getenv("ENABLE_TTS_OUTPUT", "true").lower() == "true"
MAX_PACKET_SIZE = int(os.getenv("MAX_PACKET_SIZE", "1024"))

# Cache settings
CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))
OFFLINE_CACHE_PATH = os.getenv("OFFLINE_CACHE_PATH", "/tmp/cache")

# System flags
EDGE_MODEL_PATHS = os.getenv("EDGE_MODEL_PATHS", "/tmp/models").split(",")
OFFLINE_MODE = os.getenv("OFFLINE_MODE", "false").lower() == "true"
OPTIMIZED_MODEL_DIR = os.getenv("OPTIMIZED_MODEL_DIR", "/tmp/optimized")
ALLOW_MODEL_DOWNLOAD = os.getenv("ALLOW_MODEL_DOWNLOAD", "true").lower() == "true"
MODEL_DOWNLOAD_KEY = os.getenv("MODEL_DOWNLOAD_KEY", "default_key")
ENABLE_TRANSLATION = os.getenv("ENABLE_TRANSLATION", "true").lower() == "true"
ENABLE_TTS = os.getenv("ENABLE_TTS", "true").lower() == "true"
ROUTING_AES_KEY = os.getenv("ROUTING_AES_KEY", "default_routing_key")
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"
ENABLE_DIAGNOSTICS = os.getenv("ENABLE_DIAGNOSTICS", "true").lower() == "true"
ESCALATION_ENABLED = os.getenv("ESCALATION_ENABLED", "true").lower() == "true"
TRACK_LATENCY = os.getenv("TRACK_LATENCY", "true").lower() == "true"

# Feedback settings
FEEDBACK_TTL = int(os.getenv("FEEDBACK_TTL", "86400"))
FEEDBACK_ROUTING_MODE = os.getenv("FEEDBACK_ROUTING_MODE", "round_robin")

# Voice encryption
VOICE_ENCRYPTION_KEY = os.getenv("VOICE_ENCRYPTION_KEY", "default_voice_key")

# Ultrasonic pairing
ULTRASONIC_FREQ_RANGE = os.getenv("ULTRASONIC_FREQ_RANGE", "18000-22000").split("-")

# Threat detection
THREAT_THRESHOLD = float(os.getenv("THREAT_THRESHOLD", "0.7"))
ZKP_THRESHOLD = float(os.getenv("ZKP_THRESHOLD", "0.8"))
TRUSTED_PATHS = os.getenv("TRUSTED_PATHS", "/api,/health").split(",")

# Store transcripts
STORE_TRANSCRIPTS = os.getenv("STORE_TRANSCRIPTS", "true").lower() == "true"

# Buffer settings
MAX_BUFFER_LENGTH = int(os.getenv("MAX_BUFFER_LENGTH", "100"))
CLAUSE_TIMEOUT = int(os.getenv("CLAUSE_TIMEOUT", "500"))
MAX_BUFFER_SIZE_MB = int(os.getenv("MAX_BUFFER_SIZE_MB", "50"))

# User preferences
DEFAULT_LANGUAGES = ["en", "es", "fr"]
