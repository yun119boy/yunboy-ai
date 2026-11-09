
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="yunboy AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yunboy-ai.vercel.app"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

@app.get("/")
def home():
    return {
        "status": "online",
        "message": "yunboy AI Backend is running"
    }

@app.post("/chat")
def chat(data: dict):
    message = data.get("message", "")

    return {
        "reply": f"ได้รับข้อความแล้ว: {message}"
    }
