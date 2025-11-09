import os
import time
import re
import hashlib
import logging
import subprocess
import html
import asyncio
from typing import List, Dict, Optional, Any
from filelock import FileLock
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Custom SecurityError for integrity/tampering issues
class SecurityError(Exception):
    pass

# --- Placeholder Imports for non-existent modules ---
def detect_language(text: str) -> str:
    """Placeholder for language detection."""
    return "en"

SUPPORTED_LANGS = ["en", "hi", "ta", "te", "bn"]

def get_lang_model(lang_code: str, model_type: str) -> str:
    """Placeholder for getting a language model."""
    return f"models/{lang_code}_ner_model.pt"

def validate_ner_access(user_token: str, zk_proof: str) -> bool:
    """Placeholder for ZKP authentication."""
    return True

def verify_model_hash(model_hash: str, model_name: str) -> bool:
    """Placeholder for model hash verification."""
    return True

def trigger_auto_wipe(component: str):
    """Placeholder for triggering an auto-wipe."""
    logging.info(f"Placeholder: Auto-wipe triggered for {component}")

def rotate_endpoints(service: str):
    """Placeholder for rotating endpoints."""
    logging.info(f"Placeholder: Rotating endpoints for {service}")

def deploy_honeypot(resource: str):
    """Placeholder for deploying a honeypot."""
    logging.info(f"Placeholder: Deploying honeypot for {resource}")

def register_entity_handler(handler: Any):
    """Placeholder for registering an entity handler."""
    logging.info("Placeholder: Registered entity handler")


# Corrected Internal imports
from backend.app.utils.logger import log_event, BaseLogger
from security.blockchain.zkp_handler import ZKPHandler as ZKPAuthenticator

# Security constants
NER_MODEL_DIR = os.path.abspath("ai_models/translation/ner_models")
_MODEL_LOCK = os.path.join(NER_MODEL_DIR, ".lock")
MAX_NER_RATE = 10
BLACKHOLE_DELAY = 60
RATE_LIMIT_WINDOW = 60
TEMP_NER_PATHS = ["/tmp/ivish_ner_*", "/dev/shm/ner_*"]

# AES-256-GCM encryption
MODEL_AES_KEY = os.getenv("MODEL_AES_KEY", os.urandom(32))
if len(MODEL_AES_KEY) != 32:
    raise RuntimeError("Invalid encryption key for NER model: expected 32 bytes for AES-256, got {} bytes.".format(len(MODEL_AES_KEY)))

_loaded_models = {}

logger = BaseLogger("NERTagger")

class NERModel:
    def __init__(self, model, lang: str, model_hash: str):
        self.model = model
        self.lang = lang
        self.hash = model_hash
        self._cipher = Cipher(
            algorithms.AES(MODEL_AES_KEY),
            modes.GCM(os.urandom(12)),
            backend=default_backend()
        )

class NERTagger:
    def __init__(self):
        self._request_count = 0
        self._window_start = time.time()
        self._last_reset = time.time()
        self._cipher = Cipher(
            algorithms.AES(MODEL_AES_KEY),
            modes.GCM(os.urandom(12)),
            backend=default_backend()
        )

    def _reset_rate_limit(self):
        now = time.time()
        if now - self._window_start > RATE_LIMIT_WINDOW:
            self._request_count = 0
            self._window_start = now

    async def _validate_rate_limit(self) -> bool:
        self._reset_rate_limit()
        self._request_count += 1
        if self._request_count > MAX_NER_RATE:
            await log_event("[SECURITY] NER rate limit exceeded", level="ALERT")
            await self._trigger_blackhole()
            return False
        return True

    async def _trigger_blackhole(self):
        logging.warning(f"Blackhole activated for {BLACKHOLE_DELAY}s")
        await asyncio.sleep(BLACKHOLE_DELAY)

    async def _secure_wipe(self, paths: list):
        for path in paths:
            try:
                await asyncio.to_thread(subprocess.run, ['shred', '-u', path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error(f"Secure wipe failed for {path}: {e}")

    async def authenticate_ner(self, user_token: str, zk_proof: str) -> bool:
        if not await self._validate_rate_limit():
            return False
        is_authorized = await validate_ner_access(user_token, zk_proof)
        if not is_authorized:
            await log_event(f"[SECURITY] Unauthorized NER access for {user_token[:6]}...", level="ALERT")
            await self._trigger_blackhole()
        return is_authorized

    async def load_model(self, lang_code: str, user_token: str = "", zk_proof: str = "") -> Optional[NERModel]:
        if lang_code not in SUPPORTED_LANGS:
            await log_event(f"[NER] Language not supported: {lang_code}", level="ALERT")
            return None

        if user_token and not await self.authenticate_ner(user_token, zk_proof):
            return None

        try:
            with FileLock(_MODEL_LOCK):
                if lang_code in _loaded_models:
                    return _loaded_models[lang_code]

                model_path = get_lang_model(lang_code, "ner")
                if not await self.validate_model_signature(model_path):
                    raise SecurityError("Model integrity check failed")

                # Load model securely
                if lang_code == 'en':
                    import spacy
                    nlp = spacy.load("en_core_web_sm", disable=["parser", "tagger"])
                elif lang_code in ['hi', 'ta', 'te', 'bn']:
                    import stanza
                    stanza.download(lang_code)
                    nlp = stanza.Pipeline(lang_code, processors="tokenize,ner")
                else:
                    from transformers import pipeline
                    nlp = pipeline("ner", model=model_path, framework="pt")

                model_hash = await self._compute_model_hash(model_path)
                _loaded_models[lang_code] = NERModel(nlp, lang_code, model_hash)

                await log_event(f"[NER] Model loaded for {lang_code}")
                return _loaded_models[lang_code]

        except Exception as e:
            await log_event(f"[NER] Model load failed: {str(e)}", level="ALERT")
            await trigger_auto_wipe(component="ner_model")
            return None

    async def _compute_model_hash(self, model_path: str) -> str:
        with open(model_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    async def validate_model_signature(self, model_path: str) -> bool:
        model_hash = await self._compute_model_hash(model_path)
        return await verify_model_hash(model_hash, "ner_model")

    async def extract_entities(self, text: str, lang_code: Optional[str] = None, user_token: str = "", zk_proof: str = "") -> List[Dict]:
        if not await self._validate_rate_limit():
            return []

        if user_token and not await self.authenticate_ner(user_token, zk_proof):
            return []

        try:
            text = text[:10000]
            if not text:
                return []

            if not lang_code:
                lang_code = await asyncio.to_thread(detect_language, text[:500])

            model = await self.load_model(lang_code, user_token, zk_proof)
            if not model:
                return []

            doc = model.model(text)
            entities = []

            if lang_code == 'en':
                entities = [
                    {
                        "text": ent.text,
                        "label": ent.label_,
                        "start": ent.start_char,
                        "end": ent.end_char,
                        "hash": hashlib.sha256(ent.text.encode("utf-8")).hexdigest()
                    }
                    for ent in doc.ents
                ]
            else:
                for sent in getattr(doc, "sentences", [doc]):
                    for ent in getattr(sent, "ents", []):
                        entities.append({
                            "text": ent.text,
                            "label": ent.type,
                            "start": ent.start_char,
                            "end": ent.end_char,
                            "hash": hashlib.sha256(ent.text.encode("utf-8")).hexdigest()
                        })

            await log_event(f"[NER] Extracted {len(entities)} entities for {lang_code}")
            return entities

        except Exception as e:
            await log_event(f"[NER] Extraction failed: {str(e)}", level="ALERT")
            return []

    async def highlight_entities(self, text: str, entities: List[Dict]) -> str:
        if not entities or len(text) > 100000:
            return text

        entities = sorted(
            [e for e in entities if 0 <= e['start'] < e['end'] <= len(text)],
            key=lambda x: x['start'],
            reverse=True
        )

        for ent in entities:
            try:
                label = re.sub(r"[^A-Z_]", "", ent.get("label", ""))[:20]
                wrapped = f"<ner class='{label}' data-hash='{ent['hash']}'>{html.escape(ent['text'])}</ner>"
                text = text[:ent['start']] + wrapped + text[ent['end']:]
            except Exception:
                continue
        return text

    def get_entity_labels(self, lang_code: str) -> List[str]:
        ALLOWED_LABELS = {
            'en': ["PERSON", "ORG", "LOC", "DATE", "GPE"],
            'hi': ["PER", "LOC", "ORG", "DATE"],
            'default': ["PER", "LOC", "ORG"]
        }
        return ALLOWED_LABELS.get(lang_code, ALLOWED_LABELS['default'])

    def register_with_translation_pipeline(self):
        # Placeholder for translation core
        pass

ner_tagger = Nertagger()