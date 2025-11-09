#!/usr/bin/env python3
"""
Simple test server for testing avatar update endpoint
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'Backend 3.0 3', 'VerbX-App', 'ivish'))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.routes.user import router as user_router

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include user router
app.include_router(user_router)

@app.get("/")
def read_root():
    return {"message": "Test server running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
