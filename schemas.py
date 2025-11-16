"""
Database Schemas for Trading SaaS

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercase of the class name (User -> "user").
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    avatar_url: Optional[str] = Field(None, description="Profile image URL")
    is_active: bool = Field(True, description="Account active flag")

class Chart(BaseModel):
    user_id: str = Field(..., description="Owner user id as string")
    title: str = Field(..., description="Chart title")
    symbol: str = Field(..., description="Ticker symbol, e.g., BTCUSD")
    timeframe: str = Field(..., description="Timeframe, e.g., 1H, 4H, 1D")
    notes: Optional[str] = Field(None, description="User notes")
    image_base64: str = Field(..., description="Base64 data URL of the chart image")

class Analysis(BaseModel):
    chart_id: str = Field(..., description="Related chart id")
    user_id: str = Field(..., description="Owner user id")
    summary: str = Field(..., description="AI-generated summary")
    signals: List[str] = Field(default_factory=list, description="Detected signals")
    risk_level: str = Field(..., description="low | medium | high")
    created_at: Optional[datetime] = None
