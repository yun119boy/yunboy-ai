
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
PENDING_SESSION_MINUTES = 5

COOKIE_NAME = "yunboy_admin_session"
PENDING_COOKIE_NAME = "yunboy_admin_pending"

ISSUER = "yunboy-ai"


# =========================
# APP
# =========================

app = FastAPI(
    title="yunboy AI",
    description="yunboy AI Backend API",
    version="2.1.0",
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
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json"
    }


def otp_digest(otp: str) -> str:
    return hmac.new(
        ADMIN_SESSION_SECRET.encode(),
        ("otp:" + otp).encode(),
        hashlib.sha256
    ).hexdigest()


def pending_digest(token: str) -> str:
    return hmac.new(
        ADMIN_SESSION_SECRET.encode(),
        ("pending:" + token).encode(),
        hashlib.sha256
    ).hexdigest()


def supabase_request(method: str, path: str, **kwargs):
    check_config()

    headers = service_headers()
    headers.update(kwargs.pop("headers", {}))

    try:
        response = httpx.request(
            method,
            f"{SUPABASE_URL}/rest/v1/{path}",
            headers=headers,
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


def check_admin_role(user_id: str):
    result = supabase_request(
        "GET",
        "profiles",
        params={
            "id": f"eq.{user_id}",
            "select": "role",
            "limit": "1"
        }
    ).json()

    if not result or result[0].get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access denied"
        )


def send_otp_email(email: str, otp: str):
    try:
        result = httpx.post(
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

        result.raise_for_status()

    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="Unable to send verification email"
        )


def create_pending_token(user_id: str, email: str) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": user_id,
        "email": email,
        "typ": "pending_admin",
        "iss": ISSUER,
        "aud": "yunboy-admin-pending",
        "iat": now,
        "exp": now + timedelta(minutes=PENDING_SESSION_MINUTES),
        "jti": secrets.token_urlsafe(32)
    }

    return jwt.encode(
        payload,
        ADMIN_SESSION_SECRET,
        algorithm="HS256"
    )


def create_admin_session(user_id: str, email: str) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": user_id,
        "email": email,
        "role": "admin",
        "typ": "admin",
        "iss": ISSUER,
        "aud": "yunboy-admin",
        "iat": now,
        "exp": now + timedelta(hours=ADMIN_SESSION_HOURS),
        "jti": secrets.token_urlsafe(32)
    }

    return jwt.encode(
        payload,
        ADMIN_SESSION_SECRET,
        algorithm="HS256"
    )


def decode_pending_token(token: str):
    try:
        payload = jwt.decode(
            token,
            ADMIN_SESSION_SECRET,
            algorithms=["HS256"],
            issuer=ISSUER,
            audience="yunboy-admin-pending"
        )

        if payload.get("typ") != "pending_admin":
            raise ValueError("Invalid token type")

        return payload

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Login verification expired. Please login again."
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
            issuer=ISSUER,
            audience="yunboy-admin"
        )

        if (
            payload.get("role") != "admin"
            or payload.get("typ") != "admin"
        ):
            raise ValueError("Invalid role")

        # Check current admin permission again
        check_admin_role(payload["sub"])

        return payload

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired admin session"
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
def admin_login(data: AdminLoginRequest, response: Response):
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

        # Check admin permission
        check_admin_role(user_id)

        now = datetime.now(timezone.utc)

        # Resend cooldown
        recent = supabase_request(
            "GET",
            "admin_otp_challenges",
            params={
                "user_id": f"eq.{user_id}",
                "created_at": f"gte.{(now - timedelta(seconds=OTP_RESEND_SECONDS)).isoformat()}",
                "select": "id",
                "limit": "1"
            }
        ).json()

        if recent:
            raise HTTPException(
                status_code=429,
                detail="Please wait before requesting another OTP"
            )

        # Maximum 5 requests per hour
        hourly = supabase_request(
            "GET",
            "admin_otp_challenges",
            params={
                "user_id": f"eq.{user_id}",
                "created_at": f"gte.{(now - timedelta(hours=1)).isoformat()}",
                "select": "id",
                "limit": "5"
            }
        ).json()

        if len(hourly) >= 5:
            raise HTTPException(
                status_code=429,
                detail="Too many OTP requests"
            )

        otp = f"{secrets.randbelow(1000000):06d}"
        expires_at = now + timedelta(minutes=OTP_EXPIRE_MINUTES)

        pending_token = create_pending_token(user_id, email)
        pending_hash = pending_digest(pending_token)

        # Invalidate previous unused challenges
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

        # Store OTP hash and pending token hash
        supabase_request(
            "POST",
            "admin_otp_challenges",
            headers={"Prefer": "return=minimal"},
            json={
                "user_id": user_id,
                "otp_hash": otp_digest(otp),
                "pending_token_hash": pending_hash,
                "expires_at": expires_at.isoformat()
            }
        )

        # Send email
        try:
            send_otp_email(email, otp)
        except HTTPException:
            # Invalidate challenge if email delivery fails
            supabase_request(
                "PATCH",
                "admin_otp_challenges",
                params={
                    "pending_token_hash": f"eq.{pending_hash}",
                    "consumed_at": "is.null"
                },
                json={
                    "consumed_at": datetime.now(timezone.utc).isoformat()
                }
            )
            raise

        # Set browser-bound pending cookie
        response.set_cookie(
            key=PENDING_COOKIE_NAME,
            value=pending_token,
            max_age=PENDING_SESSION_MINUTES * 60,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/api/index"
        )

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
def verify_admin_otp(
    data: OTPVerifyRequest,
    response: Response,
    request: Request
):
    check_config()

    pending_token = request.cookies.get(PENDING_COOKIE_NAME)

    if not pending_token:
        raise HTTPException(
            status_code=401,
            detail="Login verification expired. Please login again."
        )

    payload = decode_pending_token(pending_token)

    user_id = payload.get("sub")
    email = payload.get("email")

    if not user_id or not email:
        raise HTTPException(
            status_code=401,
            detail="Invalid pending login"
        )

    pending_hash = pending_digest(pending_token)

    # Verify and consume OTP atomically in Supabase
    result = supabase_request(
        "POST",
        "rpc/verify_admin_otp",
        json={
            "p_pending_token_hash": pending_hash,
            "p_otp_hash": otp_digest(data.otp),
            "p_now": datetime.now(timezone.utc).isoformat()
        }
    ).json()

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=503,
            detail="Invalid verification response"
        )

    status = result.get("status")

    if status == "invalid":
        raise HTTPException(
            status_code=401,
            detail="Incorrect verification code"
        )

    if status == "expired":
        raise HTTPException(
            status_code=401,
            detail="Verification code expired"
        )

    if status == "locked":
        raise HTTPException(
            status_code=429,
            detail="Too many incorrect attempts"
        )

    if status == "used":
        raise HTTPException(
            status_code=401,
            detail="Verification code already used"
        )

    if status != "success":
        raise HTTPException(
            status_code=401,
            detail="Verification failed"
        )

    if result.get("user_id") != user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid login session"
        )

    # Check admin role again before creating session
    check_admin_role(user_id)

    session_token = create_admin_session(user_id, email)

    response.set_cookie(
        key=COOKIE_NAME,
        value=session_token,
        max_age=ADMIN_SESSION_HOURS * 60 * 60,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/api/index"
    )

    # Remove pending login cookie
    response.delete_cookie(
        key=PENDING_COOKIE_NAME,
        path="/api/index",
        secure=True,
        httponly=True,
        samesite="lax"
    )

    return {
        "status": "authenticated",
        "authenticated": True,
        "email": email,
        "role": "admin"
    }


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

    response.delete_cookie(
        key=PENDING_COOKIE_NAME,
        path="/api/index",
        secure=True,
        httponly=True,
        samesite="lax"
    )

    return {
        "status": "logged_out"
    }
