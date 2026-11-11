
import os
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import httpx
import jwt

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# =========================
# CONFIGURATION
# =========================

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.getenv(
    "RESEND_FROM_EMAIL",
    "onboarding@resend.dev"
)

ADMIN_SESSION_SECRET = os.getenv("ADMIN_SESSION_SECRET", "")

OTP_EXPIRE_MINUTES = 5
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_SECONDS = 60
ADMIN_SESSION_HOURS = 8

COOKIE_NAME = "yunboy_admin_session"


# =========================
# APP
# =========================

app = FastAPI(
    title="yunboy AI",
    description="yunboy AI Backend API",
    version="2.0.0",
    docs_url="/api/index/docs",
    openapi_url="/api/index/openapi.json",
    redoc_url="/api/index/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yunboy-ai.vercel.app"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# =========================
# REQUEST MODELS
# =========================

class ChatRequest(BaseModel):
    message: str = ""


class AdminLoginRequest(BaseModel):
    email: str
    password: str


class OTPVerifyRequest(BaseModel):
    otp: str = Field(pattern=r"^[0-9]{6}$")


# =========================
# HELPERS
# =========================

def check_config():
    required = {
        "SUPABASE_URL": SUPABASE_URL,
        "SUPABASE_ANON_KEY": SUPABASE_ANON_KEY,
        "SUPABASE_SERVICE_ROLE_KEY": SUPABASE_SERVICE_ROLE_KEY,
        "RESEND_API_KEY": RESEND_API_KEY,
        "RESEND_FROM_EMAIL": RESEND_FROM_EMAIL,
        "ADMIN_SESSION_SECRET": ADMIN_SESSION_SECRET,
    }

    missing = [key for key, value in required.items() if not value]

    if missing:
        raise HTTPException(
            status_code=503,
            detail="Server configuration is incomplete"
        )


def service_headers():
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json"
    }


def otp_digest(otp: str) -> str:
    return hmac.new(
        ADMIN_SESSION_SECRET.encode(),
        otp.encode(),
        hashlib.sha256
    ).hexdigest()


def send_otp_email(email: str, otp: str):
    response = httpx.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "from": RESEND_FROM_EMAIL,
            "to": [email],
            "subject": "yunboy AI - Admin Verification Code",
            "html": f"""
                <div style="font-family:Arial,sans-serif">
                    <h2>yunboy AI Admin Verification</h2>
                    <p>Your verification code is:</p>
                    <h1 style="letter-spacing:8px">{otp}</h1>
                    <p>This code expires in 5 minutes.</p>
                    <p>If you did not request this code,
                    please ignore this email.</p>
                </div>
            """
        },
        timeout=15
    )

    if response.status_code not in (200, 201):
        raise HTTPException(
            status_code=502,
            detail="Unable to send verification email"
        )


def create_admin_session(user_id: str, email: str) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": user_id,
        "email": email,
        "role": "admin",
        "iss": "yunboy-ai",
        "aud": "yunboy-admin",
        "iat": now,
        "exp": now + timedelta(hours=ADMIN_SESSION_HOURS)
    }

    return jwt.encode(
        payload,
        ADMIN_SESSION_SECRET,
        algorithm="HS256"
    )


def get_admin_session(request: Request):
    check_config()

    token = request.cookies.get(COOKIE_NAME)

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Admin authentication required"
        )

    try:
        payload = jwt.decode(
            token,
            ADMIN_SESSION_SECRET,
            algorithms=["HS256"],
            issuer="yunboy-ai",
            audience="yunboy-admin"
        )

        if payload.get("role") != "admin":
            raise ValueError("Invalid role")

        return payload

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired admin session"
        )


def supabase_request(method: str, path: str, **kwargs):
    check_config()

    try:
        response = httpx.request(
            method,
            f"{SUPABASE_URL}/rest/v1/{path}",
            headers=service_headers(),
            timeout=15,
            **kwargs
        )
        response.raise_for_status()
        return response

    except httpx.HTTPError:
        raise HTTPException(
            status_code=503,
            detail="Supabase database request failed"
        )


# =========================
# HEALTH CHECK
# =========================

@app.get("/")
@app.get("/api")
@app.get("/api/index")
def home():
    return {
        "status": "online",
        "message": "yunboy AI Backend is running"
    }


# =========================
# CHAT API
# =========================

@app.post("/chat")
@app.post("/api/chat")
@app.post("/api/index/chat")
def chat(data: ChatRequest):
    return {
        "reply": "ได้รับข้อความแล้ว: " + data.message
    }


# =========================
# ADMIN LOGIN
# =========================

@app.post("/api/index/admin/login")
def admin_login(data: AdminLoginRequest):
    check_config()

    try:
        # Authenticate with Supabase Auth
        auth_response = httpx.post(
            f"{SUPABASE_URL}/auth/v1/token",
            params={"grant_type": "password"},
            headers={
                "apikey": SUPABASE_ANON_KEY,
                "Content-Type": "application/json"
            },
            json={
                "email": data.email,
                "password": data.password
            },
            timeout=15
        )

        if auth_response.status_code != 200:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )

        auth_data = auth_response.json()
        user = auth_data.get("user", {})

        user_id = user.get("id")
        email = user.get("email")

        if not user_id or not email:
            raise HTTPException(
                status_code=401,
                detail="Authentication failed"
            )

        # Check admin role in database
        profile_response = supabase_request(
            "GET",
            "profiles",
            params={
                "id": f"eq.{user_id}",
                "select": "role",
                "limit": "1"
            }
        )

        profiles = profile_response.json()

        if not profiles or profiles[0].get("role") != "admin":
            raise HTTPException(
                status_code=403,
                detail="Admin access denied"
            )

        now = datetime.now(timezone.utc)

        # Rate limit: no resend within 60 seconds
        recent_response = supabase_request(
            "GET",
            "admin_otp_challenges",
            params={
                "user_id": f"eq.{user_id}",
                "created_at": f"gte.{(now - timedelta(seconds=OTP_RESEND_SECONDS)).isoformat()}",
                "select": "id",
                "limit": "1"
            }
        )

        if recent_response.json():
            raise HTTPException(
                status_code=429,
                detail="Please wait before requesting another OTP"
            )

        # Rate limit: maximum 5 requests per hour
        hourly_response = supabase_request(
            "GET",
            "admin_otp_challenges",
            params={
                "user_id": f"eq.{user_id}",
                "created_at": f"gte.{(now - timedelta(hours=1)).isoformat()}",
                "select": "id",
                "limit": "5"
            }
        )

        if len(hourly_response.json()) >= 5:
            raise HTTPException(
                status_code=429,
                detail="Too many OTP requests"
            )

        otp = f"{secrets.randbelow(1000000):06d}"
        expires_at = now + timedelta(minutes=OTP_EXPIRE_MINUTES)

        # Invalidate previous challenges
        supabase_request(
            "PATCH",
            "admin_otp_challenges",
            params={
                "user_id": f"eq.{user_id}",
                "consumed_at": "is.null"
            },
            json={
                "consumed_at": now.isoformat()
            }
        )

        # Store only OTP hash
        supabase_request(
            "POST",
            "admin_otp_challenges",
            headers={"Prefer": "return=minimal"},
            json={
                "user_id": user_id,
                "otp_hash": otp_digest(otp),
                "expires_at": expires_at.isoformat()
            }
        )

        # Send email
        send_otp_email(email, otp)

        return {
            "status": "otp_sent",
            "message": "Verification code sent to admin email",
            "expires_in": OTP_EXPIRE_MINUTES * 60
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Admin login failed"
        )


# =========================
# VERIFY OTP
# =========================

@app.post("/api/index/admin/verify-otp")
def verify_admin_otp(data: OTPVerifyRequest, response: Response, request: Request):
    check_config()

    # This endpoint uses a temporary identity established by
    # a pending OTP challenge. The email/password login endpoint
    # must be followed by verification of the latest challenge.

    raise HTTPException(
        status_code=501,
        detail="OTP verification requires the pending-login flow to be completed"
    )


# =========================
# ADMIN SESSION CHECK
# =========================

@app.get("/api/index/admin/me")
def admin_me(request: Request):
    session = get_admin_session(request)

    return {
        "authenticated": True,
        "email": session.get("email"),
        "role": "admin"
    }


# =========================
# ADMIN LOGOUT
# =========================

@app.post("/api/index/admin/logout")
def admin_logout(response: Response):
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/api/index",
        secure=True,
        httponly=True,
        samesite="lax"
    )

    return {
        "status": "logged_out"
    }
