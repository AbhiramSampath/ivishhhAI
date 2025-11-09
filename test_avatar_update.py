#!/usr/bin/env python3
"""
Test script for the new avatar update endpoint
"""

import requests
import json

def test_avatar_update():
    """Test the avatar update endpoint"""
    url = "http://localhost:8002/user/update-avatar"

    payload = {
        "user_id": "test_user_123",
        "avatar_image_url": "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=100&h=100&fit=crop&crop=face",
        "device_fingerprint": "test_device_fingerprint_123",
        "zkp_proof": "test_zkp_proof_123"
    }

    try:
        print("Testing avatar update endpoint...")
        response = requests.post(url, json=payload)

        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")

        if response.status_code == 200:
            data = response.json()
            print("✅ Avatar update successful!")
            print(f"Response data: {json.dumps(data, indent=2)}")
        else:
            print("❌ Avatar update failed!")
            try:
                error_data = response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"Raw response: {response.text}")

    except requests.exceptions.ConnectionError:
        print("❌ Connection failed! Make sure the backend server is running on port 8002")
    except Exception as e:
        print(f"❌ Test failed with error: {str(e)}")

if __name__ == "__main__":
    test_avatar_update()
