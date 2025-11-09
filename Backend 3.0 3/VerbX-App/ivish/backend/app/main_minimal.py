import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .routes.stt import stt_router
from .routes.translate import translate_router
from .routes.chat import router as chat_router
from .routes.phrasebook import router as phrasebook_router
from ..realtime.socketio.manager import SecureSocketIOManager

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

# Include routers
app.include_router(stt_router, prefix="/stt")
app.include_router(translate_router, prefix="/translate")
app.include_router(chat_router)
app.include_router(phrasebook_router)

# Socket.IO integration
socket_manager = SecureSocketIOManager()
socket_manager.register_handlers(app)

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    logging.info("🚀 Ivish backend starting up...")

@app.on_event("shutdown")
async def shutdown_event():
    logging.info("🛑 Ivish backend shutting down...")
