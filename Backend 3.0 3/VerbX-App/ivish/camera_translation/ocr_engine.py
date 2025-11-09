import os
try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    import numpy as np
    from PIL import Image
    import io
import numpy as np
import hashlib
import logging
import re
import asyncio
import pytesseract
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --- Placeholder Imports for non-existent modules ---
def enhance_image_for_ocr(img: np.ndarray) -> np.ndarray:
    """Placeholder for image enhancement."""
    return img

def detect_language_from_text(text: str) -> str:
    """Placeholder for language detection from text."""
    return "en"

def validate_image_integrity(img: np.ndarray) -> bool:
    """Placeholder for image integrity validation."""
    return True

def get_ocr_session_token() -> str:
    """Placeholder for getting a session token."""
    return str(hashlib.sha256(os.urandom(32)).hexdigest()[:16])

def log_to_blockchain(event_type: str, payload: Dict):
    """Placeholder for blockchain logging."""
    logging.info(f"Placeholder: Log to blockchain - {event_type}")

def verify_tesseract_integrity() -> bool:
    """Placeholder for verifying Tesseract integrity."""
    return True

def verify_easyocr_integrity() -> bool:
    """Placeholder for verifying EasyOCR integrity."""
    return True

def verify_paddleocr_integrity() -> bool:
    """Placeholder for verifying PaddleOCR integrity."""
    return True

def rotate_keys():
    """Placeholder for rotating ZKP keys."""
    pass

def activate_intrusion_response():
    """Placeholder for activating intrusion response."""
    pass

# Corrected Internal imports
from backend.app.utils.logger import log_event, BaseLogger
from security.blockchain.zkp_handler import ZKPAuthenticator
from security.blockchain.blockchain_utils import BlockchainOCREngineLogger

# 🔐 Security Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# 🔐 Security Constants
_BACKEND = default_backend()
_HMAC_KEY = os.getenv("OCR_ENGINE_SIGNATURE_KEY", os.urandom(32))
_SALT = os.urandom(16)
_KDF_ITERATIONS = 100000
_MAX_RESOLUTION = 4096
_MAX_TEXT_LENGTH = 5000
_LATENCY_BUDGET_MS = 100
_SUPPORTED_LANGS = ['en', 'hi', 'ta', 'te', 'bn', 'kn', 'ml', 'mr', 'ur']
_FALLBACK_ENGINE = "tesseract"

logger = BaseLogger("SecureOCREngine")

@dataclass
class OCRResult:
    text: str
    language: str
    boxes: Optional[List[Tuple[int, int]]] = None
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    _signature: Optional[str] = None

class SecureOCREngine:
    def __init__(self):
        self.session_token = get_ocr_session_token()
        self.audit_logger = BlockchainOCREngineLogger()
        self.active_engine = self._select_secure_engine()
        self.supported_langs = _SUPPORTED_LANGS
        self._max_text_length = _MAX_TEXT_LENGTH

    def _sign_result(self, result: Dict) -> str:
        hmac_ctx = HMAC(_HMAC_KEY, hashes.SHA256(), backend=_BACKEND)
        hmac_ctx.update(json.dumps(result, sort_keys=True).encode())
        return hmac_ctx.finalize().hex()

    def _select_secure_engine(self) -> str:
        if self._is_easyocr_secure():
            return "easyocr"
        elif self._is_tesseract_secure():
            return "tesseract"
        elif self._is_paddleocr_secure():
            return "paddleocr"
        else:
            self.audit_logger.log_fallback("NO_VALID_ENGINE")
            raise RuntimeError("No secure OCR engine available")

    def _is_tesseract_secure(self) -> bool:
        try:
            return verify_tesseract_integrity()
        except Exception:
            return False

    def _is_easyocr_secure(self) -> bool:
        try:
            return verify_easyocr_integrity()
        except Exception:
            return False

    def _is_paddleocr_secure(self) -> bool:
        try:
            return verify_paddleocr_integrity()
        except Exception:
            return False

    def _sanitize_image(self, img: np.ndarray) -> np.ndarray:
        if not validate_image_integrity(img):
            self.audit_logger.log_attack("IMAGE_TAMPER_DETECTED")
            raise ValueError("Invalid image data")
        h, w = img.shape[:2]
        if h > _MAX_RESOLUTION or w > _MAX_RESOLUTION:
            if CV2_AVAILABLE:
                img = cv2.resize(img, (2048, 2048))
            else:
                # Fallback using PIL
                pil_img = Image.fromarray(img)
                pil_img = pil_img.resize((2048, 2048))
                img = np.array(pil_img)
            self.audit_logger.log_attack("IMAGE_DOWNSIZED", f"From {w}x{h} to 2048x2048")
        return img

    def _normalize_ocr_text(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return ""
        text = text.strip()
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'[^\w\s.,!?\'\"():;@#-]', '', text)
        return text[:_MAX_TEXT_LENGTH]

    def extract_text_from_image(self, img_path: str) -> Dict:
        try:
            if CV2_AVAILABLE:
                img = cv2.imread(img_path)
                if img is None:
                    raise ValueError("Invalid image file")
            else:
                # Fallback using PIL
                img = Image.open(img_path)
                img = np.array(img)
            result = self._process_frame(img)
            result["_signature"] = self._sign_result(result)
            return result
        except Exception as e:
            self.audit_logger.log_attack(f"STATIC_OCR_FAIL: {str(e)}")
            return OCRResult(text="", language="en", boxes=None).__dict__

    def extract_from_frame(self, frame: np.ndarray) -> Dict:
        try:
            result = self._process_frame(frame)
            result["_signature"] = self._sign_result(result)
            return result
        except Exception as e:
            self.audit_logger.log_attack(f"LIVE_OCR_FAIL: {str(e)}")
            return OCRResult(text="", language="en").__dict__

    def _process_frame(self, frame: np.ndarray) -> Dict:
        sanitized = self._sanitize_image(frame)
        processed = enhance_image_for_ocr(sanitized)
        if self.active_engine == "tesseract":
            text = pytesseract.image_to_string(processed)
        elif self.active_engine == "easyocr":
            from easyocr import Reader
            results = Reader(self.supported_langs, gpu=False, download_enabled=False).readtext(processed)
            text = " ".join([r[1] for r in results])
        elif self.active_engine == "paddleocr":
            from paddleocr import PaddleOCR
            ocr = PaddleOCR(lang='en', use_gpu=False)
            results = ocr.ocr(processed)
            text = " ".join([line[1][0] for line in results[0]])
        else:
            raise RuntimeError("Unknown OCR engine")
        clean_text = self._normalize_ocr_text(text)
        lang = self._validate_language(detect_language_from_text(clean_text))
        return OCRResult(
            text=clean_text,
            language=lang,
            boxes=None,
            confidence=1.0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            _signature=None
        ).__dict__

    def detect_text_and_boxes(self, frame: np.ndarray) -> List[Dict]:
        try:
            sanitized = self._sanitize_image(frame)
            processed = enhance_image_for_ocr(sanitized)
            boxes = []
            if self.active_engine == "easyocr":
                from easyocr import Reader
                results = Reader(self.supported_langs, gpu=False, download_enabled=False).readtext(processed)
                for res in results:
                    box, text, conf = res
                    if conf < 0.6:
                        continue
                    boxes.append({
                        "box": self._validate_bbox(box),
                        "text": self._normalize_ocr_text(text),
                        "confidence": float(conf)
                    })
            elif self.active_engine == "tesseract":
                import pytesseract
                data = pytesseract.image_to_data(processed, output_type=pytesseract.Output.DICT)
                for i in range(len(data['text'])):
                    try:
                        conf = float(data['conf'][i])
                    except (ValueError, TypeError):
                        continue
                    if conf > 60:
                        x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                        boxes.append({
                            "box": self._validate_bbox([(x, y), (x + w, y + h)]),
                            "text": self._normalize_ocr_text(data['text'][i]),
                            "confidence": conf
                        })
            elif self.active_engine == "paddleocr":
                from paddleocr import PaddleOCR
                ocr = PaddleOCR(lang='en', use_gpu=False)
                results = ocr.ocr(processed)
                for line in results[0]:
                    box, (text, conf) = line
                    if conf < 0.6:
                        continue
                    boxes.append({
                        "box": self._validate_bbox(box),
                        "text": self._normalize_ocr_text(text),
                        "confidence": float(conf)
                    })
            else:
                raise RuntimeError("Unknown OCR engine")
            return boxes
        except Exception as e:
            self.audit_logger.log_attack(f"BBOX_FAIL: {str(e)}")
            return []

    def _validate_bbox(self, bbox: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        if not isinstance(bbox, (list, tuple)) or len(bbox) < 2:
            raise ValueError("Invalid bbox format")
        validated = []
        for point in bbox:
            x, y = point
            validated.append((max(0, min(_MAX_RESOLUTION, int(x))), max(0, min(_MAX_RESOLUTION, int(y)))))
        return validated

    def _validate_language(self, lang: str) -> str:
        return lang if lang in self.supported_langs else 'en'

    def _trigger_defense_response(self):
        logging.critical("🚨 IMAGE TAMPERING DETECTED: Activating honeypot and endpoint rotation")
        ZKPAuthenticator().rotate_keys()
        try:
            os.system("iptables -A INPUT -j DROP")
        except Exception as e:
            logging.error(f"Failed to trigger firewall: {e}")




def extract_text_from_image(image) -> Dict[str, Any]:
    """
    Extract text from image using the secure OCR engine.
    This is a module-level function for easy importing.
    """
    engine = SecureOCREngine()
    if isinstance(image, str):
        # Image path
        return engine.extract_text_from_image(image)
    else:
        # Image array/frame
        return engine.extract_from_frame(image)

