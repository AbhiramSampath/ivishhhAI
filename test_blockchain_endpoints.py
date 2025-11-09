#!/usr/bin/env python3
"""
Test script for blockchain endpoints
"""

import requests
import json
import time

# Test server URL
BASE_URL = "http://localhost:8004"

def test_regenerate_did():
    """Test DID regeneration endpoint"""
    print("Testing DID regeneration...")

    payload = {
        "user_id": "test_user_123",
        "device_fingerprint": "test_device_fingerprint_123",
        "zkp_proof": "test_zkp_proof_123",
        "session_token": None
    }

    try:
        response = requests.post(f"{BASE_URL}/blockchain/regenerate-did", json=payload)
        print(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print("✅ DID regeneration successful!")
            print(f"DID: {data.get('did')}")
            print(f"Tx Hash: {data.get('tx_hash')}")
            return True
        else:
            print(f"❌ DID regeneration failed: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error testing DID regeneration: {str(e)}")
        return False

def test_export_private_key():
    """Test private key export endpoint"""
    print("\nTesting private key export...")

    payload = {
        "user_id": "test_user_123",
        "device_fingerprint": "test_device_fingerprint_123",
        "zkp_proof": "test_zkp_proof_123",
        "encryption_password": "test_password_123",
        "session_token": None
    }

    try:
        response = requests.post(f"{BASE_URL}/blockchain/export-private-key", json=payload)
        print(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print("✅ Private key export successful!")
            print(f"DID: {data.get('did')}")
            print(f"Encrypted Key Length: {len(data.get('encrypted_private_key', ''))}")
            return True
        else:
            print(f"❌ Private key export failed: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error testing private key export: {str(e)}")
        return False

def main():
    """Run all blockchain endpoint tests"""
    print("🚀 Starting blockchain endpoint tests...")
    print(f"Testing against: {BASE_URL}")

    # Wait a moment for server to be ready
    time.sleep(2)

    results = []

    # Test DID regeneration
    results.append(test_regenerate_did())

    # Test private key export
    results.append(test_export_private_key())

    # Summary
    print("
📊 Test Results:"    print(f"✅ Passed: {sum(results)}/{len(results)}")

    if all(results):
        print("🎉 All blockchain endpoint tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    exit(main())
