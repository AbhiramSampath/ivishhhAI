#!/usr/bin/env python3

import sys
import os
sys.path.append('Backend 3.0 3/VerbX-App/ivish')

from fastapi.testclient import TestClient
from backend.app.routes.user import router

# Create a test client
client = TestClient(router)

def test_get_user_details():
    response = client.get("/user/details?user_id=testuser&device_fingerprint=testfp&zkp_proof=testzkp")
    print(f"GET /user/details status: {response.status_code}")
    print(f"Response: {response.json()}")

def test_update_voice_auth():
    response = client.post("/user/update-voice-auth", json={
        "user_id": "testuser",
        "voice_auth_enabled": True,
        "device_fingerprint": "testfp",
        "zkp_proof": "testzkp"
    })
    print(f"POST /user/update-voice-auth status: {response.status_code}")
    print(f"Response: {response.json()}")

if __name__ == "__main__":
    print("Testing user routes...")
    test_get_user_details()
    test_update_voice_auth()
    print("Testing complete.")
