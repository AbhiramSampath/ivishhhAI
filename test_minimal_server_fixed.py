#!/usr/bin/env python3
"""
Minimal test server for testing avatar update endpoint
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime

class UpdateAvatarRequest(BaseModel):
    """
    📌 Request to update user avatar
    """
    user_id: str = Field(..., min_length=8, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')
    avatar_image_url: str = Field(..., min_length=10, max_length=512)
    device_fingerprint: str
    zkp_proof: str

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/user/update-avatar", status_code=status.HTTP_200_OK)
async def update_avatar(request_payload: UpdateAvatarRequest):
    """
    🔐 Update user avatar image (minimal test version)
    """
    try:
        # Mock validation - in real app, verify ZKP and rate limiting
        if request_payload.user_id != "test_user_123":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Access verification failed")

        # Mock update - in real app, update DB with new avatar URL
        print(f"Updating avatar for user {request_payload.user_id} to {request_payload.avatar_image_url}")

        response = {
            "success": True,
            "avatar_image_url": request_payload.avatar_image_url,
            "timestamp": datetime.now().isoformat()
        }
        return response

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Processing failed")

@app.get("/")
def read_root():
    return {"message": "Minimal test server running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
