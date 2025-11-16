import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson.objectid import ObjectId
import jwt
import bcrypt

from database import db, create_document, get_documents

# -----------------
# App & CORS
# -----------------
app = FastAPI(title="Trading Analysis SaaS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXPIRE_MIN = 60 * 24 * 7  # 7 days

# -----------------
# Models
# -----------------
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    token: str
    user: dict

class ChartCreate(BaseModel):
    title: str
    symbol: str
    timeframe: str
    notes: Optional[str] = None
    image_base64: str

class AnalysisResponse(BaseModel):
    id: str
    chart_id: str
    summary: str
    signals: List[str]
    risk_level: str
    created_at: datetime

# -----------------
# Helpers
# -----------------

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def create_token(user: dict) -> str:
    payload = {
        "sub": str(user.get("_id")),
        "email": user.get("email"),
        "name": user.get("name"),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MIN),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    payload = decode_token(parts[1])
    user_id = payload.get("sub")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# -----------------
# Basic Routes
# -----------------
@app.get("/")
def read_root():
    return {"message": "Trading Analysis SaaS API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# -----------------
# Auth
# -----------------
@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignupRequest):
    existing = db["user"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "avatar_url": None,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    user_doc["_id"] = res.inserted_id
    token = create_token(user_doc)
    public_user = {"id": str(user_doc["_id"]), "name": user_doc["name"], "email": user_doc["email"]}
    return {"token": token, "user": public_user}


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token(user)
    public_user = {"id": str(user["_id"]), "name": user["name"], "email": user["email"]}
    return {"token": token, "user": public_user}


# -----------------
# Charts
# -----------------
@app.post("/charts")
def create_chart(payload: ChartCreate, current_user: dict = Depends(get_current_user)):
    chart = {
        "user_id": str(current_user["_id"]),
        "title": payload.title,
        "symbol": payload.symbol.upper(),
        "timeframe": payload.timeframe,
        "notes": payload.notes,
        "image_base64": payload.image_base64,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    inserted_id = create_document("chart", chart)
    chart["_id"] = inserted_id
    return {"id": inserted_id, **{k: chart[k] for k in chart if k != "_id"}}


@app.get("/charts")
def list_charts(current_user: dict = Depends(get_current_user)):
    docs = db["chart"].find({"user_id": str(current_user["_id"])}, sort=[("created_at", -1)])
    charts = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        charts.append(d)
    return charts


# -----------------
# Simple AI Analysis (rule-based placeholder)
# -----------------

def simple_analyze(title: str, notes: Optional[str], symbol: str, timeframe: str) -> dict:
    text = f"{title} {notes or ''} {symbol} {timeframe}".lower()
    signals = []
    if any(k in text for k in ["breakout", "bo"]) or ("resistance" in text and "break" in text):
        signals.append("Potential breakout")
    if any(k in text for k in ["double top", "dt"]):
        signals.append("Double top pattern risk")
    if any(k in text for k in ["double bottom", "db"]):
        signals.append("Double bottom reversal")
    if any(k in text for k in ["support", "bounce"]):
        signals.append("Support bounce setup")
    if any(k in text for k in ["rsi", "divergence"]):
        signals.append("Momentum divergence noted")
    if not signals:
        signals.append("No strong pattern detected")
    risk = "medium"
    if "leverage" in text or "high risk" in text:
        risk = "high"
    if "hedge" in text or "tight stop" in text:
        risk = "low"
    summary = (
        f"Analysis for {symbol} on {timeframe}: "
        f"{signals[0]}. Manage risk with clear invalidation."
    )
    return {"summary": summary, "signals": signals, "risk_level": risk}


@app.post("/analyze/{chart_id}", response_model=AnalysisResponse)
def analyze_chart(chart_id: str, current_user: dict = Depends(get_current_user)):
    chart = db["chart"].find_one({"_id": ObjectId(chart_id), "user_id": str(current_user["_id"])})
    if not chart:
        raise HTTPException(status_code=404, detail="Chart not found")
    result = simple_analyze(chart.get("title", ""), chart.get("notes"), chart.get("symbol", ""), chart.get("timeframe", ""))
    doc = {
        "chart_id": chart_id,
        "user_id": str(current_user["_id"]),
        "summary": result["summary"],
        "signals": result["signals"],
        "risk_level": result["risk_level"],
        "created_at": datetime.now(timezone.utc),
    }
    inserted_id = create_document("analysis", doc)
    return AnalysisResponse(
        id=str(inserted_id),
        chart_id=chart_id,
        summary=doc["summary"],
        signals=doc["signals"],
        risk_level=doc["risk_level"],
        created_at=doc["created_at"],
    )


@app.get("/analyses")
def list_analyses(current_user: dict = Depends(get_current_user)):
    docs = db["analysis"].find({"user_id": str(current_user["_id"])}, sort=[("created_at", -1)])
    items = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        items.append(d)
    return items
