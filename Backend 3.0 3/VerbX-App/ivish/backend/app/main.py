import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

# from routes.stt import stt_router
# from routes.tts import tts_router
# from routes.translate import translate_router
# from routes.chat import router as chat_router
# from routes.diagnostic import diagnostic_router
# from routes.sentiment import sentiment_router
# from routes.collaboration import collaboration_router
# from routes.auth import auth_router
# from routes.emoji_reactions import emoji_reactions_router
# from routes.feedback import feedback_router
# from routes.gamified_learning import gamified_learning_router
# from routes.gpt import gpt_router
# from routes.health import health_router
# from routes.ivish import ivish_router
# from routes.language_switch import language_switch_router
# from routes.ner_tagger import ner_tagger_router
# from routes.permissions import permissions_router
# from routes.phrasebook import router as phrasebook_router
from routes.user import router as user_router
# from .routes.referral_rewards import referral_rewards_router
# from .routes.report_translation import report_translation_router
# from .routes.sidebar import sidebar_router
# from .routes.video_call import video_call_router
# from .routes.voice_call import voice_call_router
from middlewares.rate_limiter import RateLimiterMiddleware
from realtime.socketio.manager import SecureSocketIOManager
from security.firewall import secure_gateway
from security.intrusion_prevention.isolation_engine import isolation_engine

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip middleware
app.add_middleware(GZipMiddleware, minimum_size=500)

# Session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key="your-secret-key",  # Replace with actual secret key
    session_cookie="__Secure-IvishSess",
    max_age=86400,
    same_site="strict",
)

# HTTPS redirect middleware
# app.add_middleware(HTTPSRedirectMiddleware)

# Security middlewares - temporarily disabled to fix startup issues
# app.middleware("http")(secure_gateway)  # AI Firewall middleware
# app.add_middleware(RateLimiterMiddleware)  # Rate limiter middleware

# Include routers
# app.include_router(auth_router, prefix="/auth")
# app.include_router(stt_router, prefix="/stt")
# app.include_router(tts_router, prefix="/tts")
# app.include_router(translate_router, prefix="/translate")
# app.include_router(chat_router)
# app.include_router(diagnostic_router, prefix="/diagnostics")
# app.include_router(sentiment_router, prefix="/sentiment")
# app.include_router(collaboration_router, prefix="/collab")
# app.include_router(phrasebook_router)
app.include_router(user_router, prefix="/api/v1")

# Socket.IO integration - temporarily disabled to fix startup issues
# socket_manager = SecureSocketIOManager()
# socket_manager.register_handlers(app)

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    logging.info("🚀 Ivish backend starting up...")

@app.on_event("shutdown")
async def shutdown_event():
    logging.info("🛑 Ivish backend shutting down...")
