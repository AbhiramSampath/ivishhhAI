#!/usr/bin/env python3
"""
Minimal test server for blockchain endpoints
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import uvicorn

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RegenerateDIDRequest(BaseModel):
    user_id: str
    device_fingerprint: str
    zkp_proof: str
    session_token: str = None

class ExportPrivateKeyRequest(BaseModel):
    user_id: str
    device_fingerprint: str
    zkp_proof: str
    encryption_password: str
    session_token: str = None

@app.post("/blockchain/regenerate-did")
async def regenerate_did(request: RegenerateDIDRequest):
    """Mock DID regeneration endpoint"""
    # Simulate successful DID generation
    did = f"did:ivish:{hash(request.user_id) % 1000000:06x}"

    return {
        "success": True,
        "did": did,
        "tx_hash": f"0x{hash(request.user_id + str(datetime.now())) % 2**256:064x}",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/blockchain/export-private-key")
async def export_private_key(request: ExportPrivateKeyRequest):
    """Mock private key export endpoint"""
    # Simulate successful key export
    did = f"did:ivish:{hash(request.user_id) % 1000000:06x}"
    encrypted_key = f"encrypted_key_for_{request.user_id}_with_password_{hash(request.encryption_password)}"

    return {
        "success": True,
        "encrypted_private_key": encrypted_key,
        "did": did,
        "export_timestamp": datetime.now().isoformat(),
        "warning": "Store this encrypted key securely. Decryption requires the password provided."
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "blockchain_test_server"}

if __name__ == "__main__":
    print("🚀 Starting blockchain test server on port 8005...")
    uvicorn.run(app, host="0.0.0.0", port=8005)
