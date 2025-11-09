#!/usr/bin/env python3
"""
Test script for camera translate API endpoint
"""
import requests
import json
from pathlib import Path

def test_camera_translate_api():
    """Test the camera translate API endpoint"""

    # API endpoint
    url = "http://localhost:8000/translate-camera"

    # Test data
    test_data = {
        "image": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",  # 1x1 transparent PNG
        "target_lang": "hi",
        "source_lang": "en",
        "session_token": "test_session_token"
    }

    try:
        print("Testing camera translate API...")
        print(f"URL: {url}")
        print(f"Data: {json.dumps(test_data, indent=2)}")

        response = requests.post(url, json=test_data, timeout=10)

        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")

        if response.status_code == 200:
            result = response.json()
            print("✅ API call successful!")
            print(f"Result: {json.dumps(result, indent=2)}")
            return True
        else:
            print(f"❌ API call failed with status {response.status_code}")
            return False

    except requests.exceptions.ConnectionError:
        print("❌ Connection failed - backend server not running")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = test_camera_translate_api()
    exit(0 if success else 1)
