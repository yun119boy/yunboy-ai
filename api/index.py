from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="yunboy AI",
    description="yunboy AI Backend API",
    version="1.0.0",
    docs_url="/api/index/docs",
    openapi_url="/api/index/openapi.json",
    redoc_url="/api/index/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yunboy-ai.vercel.app"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.get("/")
@app.get("/api")
@app.get("/api/index")
def home():
    return {
        "status": "online",
        "message": "yunboy AI Backend is running"
    }

@app.post("/chat")
@app.post("/api/chat")
@app.post("/api/index/chat")
def chat(data: dict):
    message = data.get("message", "")

    return {
        "reply": "ได้รับข้อความแล้ว: " + message
    }
