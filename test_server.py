#!/usr/bin/env python3
"""
Simple test server for testing avatar update endpoint
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from Backend_3_0_3.VerbX_App.ivish.backend.app.routes.user import router as user_router

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
