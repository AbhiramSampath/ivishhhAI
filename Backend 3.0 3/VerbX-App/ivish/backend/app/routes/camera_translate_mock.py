from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
import base64
import json
from datetime import datetime

router = APIRouter()

class CameraTranslateRequest(BaseModel):
    image: str
    target_lang: str
    source_lang: str
    session_token: str

@router.post("/translate-camera")
async def translate_camera(request: CameraTranslateRequest) -> Dict[str, Any]:
    """
    Mock camera translate endpoint for testing
    """
    try:
        # Validate base64 image
        try:
            base64.b64decode(request.image)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 image")

        # Mock OCR result
        mock_ocr_text = "Hello World"

        # Mock translation result
        mock_translation = {
            "hi": "नमस्ते दुनिया",
            "es": "Hola Mundo",
            "fr": "Bonjour le monde"
        }.get(request.target_lang, f"Translated text to {request.target_lang}")

        return {
            "original_text": mock_ocr_text,
            "translated_text": mock_translation,
            "source_lang": request.source_lang,
            "target_lang": request.target_lang,
            "confidence": 0.95,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_token": request.session_token
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Translation failed: {str(e)}")
