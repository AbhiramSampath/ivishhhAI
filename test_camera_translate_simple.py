#!/usr/bin/env python3
"""
Simple test for camera translate functionality
"""

import requests
import json
import base64
from PIL import Image
import io

def create_test_image():
    """Create a simple test image with text"""
    # Create a simple white image with text
    img = Image.new('RGB', (100, 50), color='white')
    # For simplicity, we'll use a base64 encoded 1x1 pixel image
    return "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

def test_camera_translate_api():
    """Test the camera translate API"""
    url = "http://localhost:8002/translate-camera"

    # Create test data
    test_data = {
        "image": create_test_image(),
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
            print("✅ API test successful!")
            return True
        else:
            print("❌ API test failed!")
            return False

    except requests.exceptions.ConnectionError:
        print("❌ Connection failed - backend server not running")
        return False
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False

if __name__ == "__main__":
    success = test_camera_translate_api()
    exit(0 if success else 1)
