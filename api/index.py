
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yunboy-ai.vercel.app"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.get("/")
@app.get("/api")
def home():
    return {
        "status": "online",
        "message": "yunboy AI Backend is running"
    }

@app.post("/chat")
def chat(data: dict):
    return {
        "reply": "ได้รับข้อความแล้ว: " + data.get("message", "")
    }
