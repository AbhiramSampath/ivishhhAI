from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .routes.camera_translate_mock import router as camera_translate_router
from .routes.user import router as user_router
from .routes.blockchain import router as blockchain_router

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
app.include_router(camera_translate_router)
app.include_router(user_router)
app.include_router(blockchain_router)

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    print("🚀 Ivish backend starting up...")

@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 Ivish backend shutting down...")
