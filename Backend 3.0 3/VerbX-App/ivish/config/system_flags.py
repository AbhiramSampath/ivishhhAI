import os

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
DEFAULT_LANG = os.getenv("DEFAULT_LANG", "en")
