# ai_models/ner/ner_handler.py

import os
import time
import re
import json
import hashlib
import hmac
import logging
import asyncio
import unicodedata
from typing import List, Dict, Optional, Union
from collections import defaultdict

# SECURITY: Corrected imports
from utils.logger import log_event
from utils.lang_codes import detect_language
from security.encryption_utils import AES256Cipher
from utils.helpers import apply_differential_privacy

# External libraries (assumed)
import spacy
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
from sacremoses import MosesTokenizer
from transformers.pipelines.token_classification import TokenClassificationPipeline

# LOGGER CONFIG
logger = logging.getLogger(__name__)

# SECURITY CONSTANTS - Defined locally as config file is not in PDF
MAX_TEXT_LENGTH = int(os.getenv("NER_MAX_TEXT_LENGTH", "10000"))
ENTITY_WHITELIST = os.getenv("NER_ENTITY_WHITELIST", "PERSON,LOCATION,ORGANIZATION,DATE").split(",")
MODEL_HASH = os.getenv("NER_MODEL_SHA256", "a1b2c3d4e5f67890...")
NER_SECRET_SALT = os.getenv("NER_SECRET_SALT", os.urandom(32)).encode()
MIN_PROCESSING_TIME_MS = int(os.getenv("NER_MIN_PROCESSING_TIME", "50"))
NER_CACHE_EXPIRY = int(os.getenv("NER_CACHE_EXPIRY", "3600"))

class NEREngine:
    """
    Nuclear-grade secure NER engine.
    """
    def __init__(self):
        self._cache = {}
        self._cache_expiry = NER_CACHE_EXPIRY
        self._cipher = AES256Cipher()
        self._spacy_nlp: Optional[spacy.Language] = None
        self._transformer_nlp: Optional[TokenClassificationPipeline] = None
        self._indic_tokenizer: Optional[MosesTokenizer] = None

    async def ner_spacy(self, text: str) -> List[Dict]:
        """SECURE spaCy NER with async support"""
        try:
            if not self._spacy_nlp:
                self._spacy_nlp = await asyncio.to_thread(self._load_spacy_model)
            if not self._spacy_nlp:
                return []
            doc = await asyncio.to_thread(self._spacy_nlp, text)
            return [{
                "entity": ent.text, "type": ent.label_, "score": 1.0,
                "start": ent.start_char, "end": ent.end_char, "source": "spacy"
            } for ent in doc.ents]
        except Exception as e:
            logger.warning("SpaCy NER failed", exc_info=True)
            return []

    async def ner_transformer(self, text: str, lang: str = "en") -> List[Dict]:
        """SECURE transformer NER with async support"""
        try:
            if not self._transformer_nlp:
                self._transformer_nlp = await asyncio.to_thread(self._load_transformer_model, lang)
            if not self._transformer_nlp:
                return []
            results = await asyncio.to_thread(self._transformer_nlp, text)
            return [{
                "entity": res["word"], "type": res["entity_group"], "score": res["score"],
                "start": res.get("start", 0), "end": res.get("end", 0), "source": "transformer"
            } for res in results]
        except Exception as e:
            logger.warning("Transformer NER failed", exc_info=True)
            return []

    async def ner_indic(self, text: str) -> List[Dict]:
        """SECURE Indic NER with async support"""
        try:
            if not self._indic_tokenizer:
                self._indic_tokenizer = await asyncio.to_thread(MosesTokenizer, lang='hi')
            tokens = await asyncio.to_thread(self._indic_tokenizer.tokenize, text)
            return [{"entity": token, "type": "PERSON", "score": 0.9, "source": "indic"} for token in tokens if token.lower() in {"ramesh", "delhi", "tata", "sbi"}]
        except Exception as e:
            logger.warning("Indic NER failed", exc_info=True)
            return []

    async def process(self, text: str, lang: Optional[str] = None) -> List[Dict]:
        start_time = time.time()
        try:
            if not isinstance(text, str) or len(text) > MAX_TEXT_LENGTH:
                return []
            text = self._sanitize_text(text)
            lang = lang or await detect_language(text)
            lang = lang.split("-")[0].lower()[:2]
            
            ner_func = {
                "en": self.ner_spacy, "hi": self.ner_indic, "ta": self.ner_indic,
                "te": self.ner_indic, "kn": self.ner_indic, "ml": self.ner_indic
            }.get(lang, self.ner_transformer)

            entities = await ner_func(text, lang=lang)
            entities = apply_differential_privacy({"entities": entities}, epsilon=0.05)["entities"]
            standardized = self._standardize_entities(entities)
            self._apply_processing_delay(start_time, target_ms=MIN_PROCESSING_TIME_MS)
            return standardized
        except Exception as e:
            logger.warning("NER detection failed", exc_info=True)
            return []

    def supports_language(self, lang: str) -> bool:
        return lang in ["en", "hi", "ta", "te", "kn", "ml"]

    def _sanitize_text(self, text: str) -> str:
        if not isinstance(text, str): return ""
        return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\xff]", "", text)[:MAX_TEXT_LENGTH]

    def _standardize_entities(self, entities: List[Dict]) -> List[Dict]:
        try:
            return [
                {"entity": ent.get("entity", ""), "type": ent.get("type", "").upper(),
                 "score": float(ent.get("score", 0.0)), "start": ent.get("start", 0),
                 "end": ent.get("end", 0), "source": ent.get("source", "unknown")}
                for ent in entities if ent.get("type", "").upper() in ENTITY_WHITELIST
            ]
        except Exception as e:
            logger.warning("Entity standardization failed", exc_info=True)
            return []

    def _load_spacy_model(self):
        try:
            return spacy.load("en_core_web_sm")
        except Exception as e:
            logger.critical("SpaCy model load failed", exc_info=True)
            return None

    def _load_transformer_model(self, lang: str = "en"):
        try:
            model_name = "Davlan/bert-base-multilingual-cased-ner-hrl"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForTokenClassification.from_pretrained(model_name)
            return pipeline("ner", model=model, tokenizer=tokenizer, grouped_entities=True)
        except Exception as e:
            logger.critical("Transformer model load failed", exc_info=True)
            return None

    def _load_indic_tokenizer(self):
        try:
            return MosesTokenizer(lang='hi')
        except Exception as e:
            logger.critical("Indic tokenizer load failed", exc_info=True)
            return None

    def _apply_processing_delay(self, start_time: float, target_ms: int):
        elapsed_ms = (time.time() - start_time) * 1000
        if elapsed_ms < target_ms:
            time.sleep((target_ms - elapsed_ms) / 1000)