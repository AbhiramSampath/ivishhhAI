import logging

from fastapi import FastAPI
from realtime.socketio.manager import SecureSocketIOManager

app = FastAPI()

socket_manager = SecureSocketIOManager()
socket_manager.register_handlers(app)

@app.get("/")
def read_root():
    return {"Hello": "World"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8003)
