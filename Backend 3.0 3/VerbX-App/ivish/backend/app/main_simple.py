from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/docs")
async def docs():
    return {"message": "Docs endpoint"}
