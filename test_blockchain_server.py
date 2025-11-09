#!/usr/bin/env python3
"""
Minimal test server for blockchain endpoints
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import uvicorn

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RegenerateDIDRequest(BaseModel):
    user_id: str
    device_fingerprint: str
    zkp_proof: str
    session_token: str = None

class ExportPrivateKeyRequest(BaseModel):
    user_id: str
    device_fingerprint: str
    zkp_proof: str
    encryption_password: str
    session_token: str = None

class SwitchLanguageRequest(BaseModel):
    user_id: str
    command: str
    session_token: str = None

class ChangePasswordRequest(BaseModel):
    user_id: str
    current_password: str
    new_password: str
    device_fingerprint: str
    zkp_proof: str
    session_token: str

class CreateAvatarRequest(BaseModel):
    user_id: str
    voice_style: str
    voice_sample: Optional[str] = None  # Base64 encoded or something
    device_fingerprint: str
    zkp_proof: str
    session_token: str

class GetUserDetailsRequest(BaseModel):
    user_id: str
    device_fingerprint: str
    zkp_proof: str

class UpdateVoiceAuthRequest(BaseModel):
    user_id: str
    voice_auth_enabled: bool
    device_fingerprint: str
    zkp_proof: str

class UpdateAvatarRequest(BaseModel):
    user_id: str
    avatar_image_url: str
    device_fingerprint: str
    zkp_proof: str

class LinkAccountRequest(BaseModel):
    account_name: str
    device_fingerprint: str
    zkp_proof: str

class UnlinkAccountRequest(BaseModel):
    account_name: str
    device_fingerprint: str
    zkp_proof: str

class SubmitFeedbackRequest(BaseModel):
    email: str
    description: str
    feedback_type: str
    user_token: str
    device_fingerprint: str
    zkp_proof: str
    attachment: Optional[str] = None

class AuthRequest(BaseModel):
    email: str
    password: str
    voice_sample: Optional[str] = None
    zkp_proof: Optional[str] = None
    device_fingerprint: str

class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int

class PersonalizationRequest(BaseModel):
    user_id: str
    device_fingerprint: str
    zkp_proof: str

class UpdateMemoryRequest(BaseModel):
    user_id: str
    memory_enabled: bool
    device_fingerprint: str
    zkp_proof: str

class UpdatePromptRequest(BaseModel):
    user_id: str
    prompt: str
    device_fingerprint: str
    zkp_proof: str

class CompleteOnboardingRequest(BaseModel):
    user_id: str
    device_fingerprint: str
    zkp_proof: str

@app.post("/blockchain/regenerate-did")
async def regenerate_did(request: RegenerateDIDRequest):
    """Mock DID regeneration endpoint"""
    # Simulate successful DID generation
    did = f"did:ivish:{hash(request.user_id) % 1000000:06x}"

    return {
        "success": True,
        "did": did,
        "tx_hash": f"0x{hash(request.user_id + str(datetime.now())) % 2**256:064x}",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/blockchain/export-private-key")
async def export_private_key(request: ExportPrivateKeyRequest):
    """Mock private key export endpoint"""
    # Simulate successful key export
    did = f"did:ivish:{hash(request.user_id) % 1000000:06x}"
    encrypted_key = f"encrypted_key_for_{request.user_id}_with_password_{hash(request.encryption_password)}"

    return {
        "success": True,
        "encrypted_private_key": encrypted_key,
        "did": did,
        "export_timestamp": datetime.now().isoformat(),
        "warning": "Store this encrypted key securely. Decryption requires the password provided."
    }

@app.post("/language/switch")
async def switch_language(request: SwitchLanguageRequest):
    """Mock language switch endpoint"""
    # Extract language from command (simple parsing)
    import re
    match = re.search(r'switch to (\w+)', request.command, re.IGNORECASE)
    if match:
        language = match.group(1)
    else:
        language = "English"  # Default

    return {
        "status": "success",
        "new_language": language,
        "language_code": language.lower()[:2],  # Simple code
        "tts_audio": f"mock_audio_for_{language}",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/user/change-password")
async def change_password(request: ChangePasswordRequest):
    """Mock change password endpoint"""
    # Simulate successful password change
    return {
        "success": True,
        "message": "Password changed successfully",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/user/create-avatar")
async def create_avatar(request: CreateAvatarRequest):
    """Mock create avatar endpoint"""
    # Simulate successful avatar creation
    return {
        "success": True,
        "message": "Avatar created successfully",
        "voice_style": request.voice_style,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/user/details")
async def get_user_details(request: GetUserDetailsRequest):
    """Mock get user details endpoint"""
    # Simulate user details
    return {
        "user_id": request.user_id,
        "name": "Test User",
        "email": "test@example.com",
        "voice_auth_enabled": True,
        "profile_image_url": "https://example.com/avatar.jpg",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/user/update-voice-auth")
async def update_voice_auth(request: UpdateVoiceAuthRequest):
    """Mock update voice auth endpoint"""
    # Simulate successful update
    return {
        "success": True,
        "voice_auth_enabled": request.voice_auth_enabled,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/user/update-avatar")
async def update_avatar(request: UpdateAvatarRequest):
    """Mock update avatar endpoint"""
    # Simulate successful update
    return {
        "success": True,
        "avatar_image_url": request.avatar_image_url,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/user/link-account")
async def link_account(request: LinkAccountRequest):
    """Mock link account endpoint"""
    # Simulate successful link
    return {
        "success": True,
        "account": request.account_name,
        "linked": True,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/user/unlink-account")
async def unlink_account(request: UnlinkAccountRequest):
    """Mock unlink account endpoint"""
    # Simulate successful unlink
    return {
        "success": True,
        "account": request.account_name,
        "linked": False,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/faq")
async def get_faqs():
    """Mock FAQ endpoint"""
    faqs = [
        {
            "id": 1,
            "question": "What is VerbX and Ivish?",
            "answer": "VerbX is your personal language companion — it helps you talk, translate, learn, and connect in multiple languages.\nIvish is the smart assistant inside VerbX — like a friend who understands your voice, emotion, and language."
        },
        {
            "id": 2,
            "question": "Do I need to speak in English to use Ivish?",
            "answer": "Nope! Ivish understands many languages including Hindi, Tamil, Telugu, Kannada, Bengali, and more.\nYou can speak in your native language or even mix them — Ivish will get it."
        },
        {
            "id": 3,
            "question": "Is it safe to use?",
            "answer": "Yes. Everything you say is encrypted. Your voiceprints are secure, and you can delete your data anytime. We don’t track or store anything without your consent."
        },
        {
            "id": 4,
            "question": "Does Ivish work offline?",
            "answer": "Yes! You can use voice-to-text, translation, and more even without internet — just download the Offline Pack in settings."
        },
        {
            "id": 5,
            "question": "How do I start a voice chat with Ivish?",
            "answer": "Just say “Hey Ivish” or tap the mic icon. Ivish will listen and reply instantly."
        },
        {
            "id": 6,
            "question": "Can I type instead of speaking?",
            "answer": "Yes! Use the Live Chat feature to type messages to Ivish if you’re in a quiet place or prefer texting."
        },
        {
            "id": 7,
            "question": "Why is Ivish repeating what I said?",
            "answer": "That’s normal — Ivish might echo short phrases to confirm understanding. You can turn this off in Settings → Voice Preferences."
        },
        {
            "id": 8,
            "question": "How do I save a useful phrase or translation?",
            "answer": "Just say “Save this” or tap the bookmark icon after any message. You’ll find your saved phrases under “My Phrasebook.”"
        },
        {
            "id": 9,
            "question": "I think Ivish misunderstood me. What can I do?",
            "answer": "No worries. You can:\n• Tap the message and choose “Rephrase” or “Translate again”\n• Or say “That’s not what I meant”\nIvish learns and improves over time."
        },
        {
            "id": 10,
            "question": "Can I use this during calls or video chats?",
            "answer": "Yes! Ivish can add live subtitles or translate voice during calls — just enable “Call Mode” in the settings."
        },
        {
            "id": 11,
            "question": "How do I change languages?",
            "answer": "Tap the language dropdown in the chat screen, or just say “Speak in Tamil from now” or “Translate to Hindi please.”"
        },
        {
            "id": 12,
            "question": "What if I forget a word or phrase?",
            "answer": "Just ask! Say “How do I say ‘Good evening’ in Bengali?”\nIvish will show and pronounce it for you."
        },
        {
            "id": 13,
            "question": "Does Ivish help with pronunciation?",
            "answer": "Yes! You’ll get instant feedback on grammar and accent. There’s even a “Practice Mode” if you want to speak back and get corrected."
        },
        {
            "id": 14,
            "question": "Is there a way to learn languages inside the app?",
            "answer": "Absolutely. Go to the Learning Hub — you’ll find short lessons, quizzes, and daily challenges. It’s fun, fast, and personalized."
        },
        {
            "id": 15,
            "question": "Can I delete everything Ivish remembers about me?",
            "answer": "Yes. Go to Settings → Privacy & Security → Wipe Memory. Your data will be deleted instantly. We respect your privacy 100%."
        },
        {
            "id": 16,
            "question": "How do I report a bug or get help?",
            "answer": "Go to Settings → Help & Support → Report an Issue.\nYou can also drop a message in the Live Support Chat, and our team will get back ASAP."
        },
    ]
    return {"faqs": faqs}

@app.post("/feedback/submit")
async def submit_feedback(request: SubmitFeedbackRequest):
    """Mock feedback submission endpoint"""
    # Log or store feedback as needed
    return {
        "success": True,
        "message": "Thank you for your feedback!",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/legal/privacy-policy")
async def get_privacy_policy():
    """Mock privacy policy endpoint"""
    return {
        "title": "Privacy Policy",
        "content": "This is the privacy policy content...",
        "last_updated": datetime.now().isoformat()
    }

@app.get("/legal/terms-conditions")
async def get_terms_conditions():
    """Mock terms and conditions endpoint"""
    return {
        "title": "Terms and Conditions",
        "content": "This is the terms and conditions content...",
        "last_updated": datetime.now().isoformat()
    }

@app.get("/legal/open-source")
async def get_open_source():
    """Mock open source endpoint"""
    return {
        "title": "Open Source Licenses",
        "licenses": [
            {
                "category": "NLP",
                "items": [
                    {"name": "LangDetect", "license": "Apache 2.0"},
                    {"name": "Sarvam AI", "license": "Open-source"}
                ]
            },
            {
                "category": "STT",
                "items": [
                    {"name": "Whisper.cpp", "license": "MIT"}
                ]
            },
            {
                "category": "TTS",
                "items": [
                    {"name": "Coqui TTS", "license": "Apache 2.0"}
                ]
            },
            {
                "category": "Security",
                "items": [
                    {"name": "PyJWT", "license": "MIT"}
                ]
            },
            {
                "category": "UI",
                "items": [
                    {"name": "FastAPI", "license": "MIT"},
                    {"name": "Flask SocketIO", "license": "MIT"},
                    {"name": "Redis", "license": "BSD"},
                    {"name": "MongoDB TTL", "license": "Server Side Public"}
                ]
            }
        ],
        "last_updated": datetime.now().isoformat()
    }

@app.post("/auth/register")
async def register_user(request: AuthRequest):
    """Mock user registration endpoint"""
    # Simulate successful registration
    user_id = f"user_{hash(request.email) % 1000000}"
    return {
        "status": "success",
        "user_id": user_id,
        "zkp_pubkey": f"zkp_key_{user_id}",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/auth/login")
async def login_user(request: AuthRequest):
    """Mock user login endpoint"""
    # Simulate successful login
    access_token = f"access_token_{hash(request.email)}"
    refresh_token = f"refresh_token_{hash(request.email)}"
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": 3600
    }

@app.post("/onboarding/complete")
async def complete_onboarding(request: CompleteOnboardingRequest):
    """Mock complete onboarding endpoint"""
    # Simulate successful completion
    return {
        "success": True,
        "message": "Onboarding completed",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/personalization/get")
async def get_personalization(request: PersonalizationRequest):
    """Mock get personalization settings endpoint"""
    # Simulate personalization data
    return {
        "memory_enabled": True,
        "recent_phrases": ["Formal", "Friendly", "Simple"],
        "prompt": "Default prompt",
        "language_test_mode": "TOEFL",
        "language_test_progress": 20,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/personalization/update-memory")
async def update_memory(request: UpdateMemoryRequest):
    """Mock update memory endpoint"""
    # Simulate successful update
    return {
        "success": True,
        "memory_enabled": request.memory_enabled,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/personalization/update-prompt")
async def update_prompt(request: UpdatePromptRequest):
    """Mock update prompt endpoint"""
    # Simulate successful update
    return {
        "success": True,
        "prompt": request.prompt,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/personalization/get-language-test")
async def get_language_test(request: PersonalizationRequest):
    """Mock get language test progress endpoint"""
    # Simulate progress
    return {
        "mode": "TOEFL",
        "progress": 20,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/personalization/reset-language-test")
async def reset_language_test(request: PersonalizationRequest):
    """Mock reset language test endpoint"""
    # Simulate reset
    return {
        "success": True,
        "progress": 0,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "blockchain_test_server"}

if __name__ == "__main__":
    print("🚀 Starting blockchain test server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
