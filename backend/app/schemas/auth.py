import re
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator
from app.schemas.user import UserResponse


class SignupRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        cleaned = v.strip()
        if len(cleaned) < 2:
            raise ValueError("Full name must be at least 2 characters long.")
        if len(cleaned) > 100:
            raise ValueError("Full name cannot exceed 100 characters.")
        return cleaned

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if len(v) > 128:
            raise ValueError("Password cannot exceed 128 characters.")
        # Check basic complexity: needs at least one number or special character
        if not re.search(r"[0-9!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one digit or special symbol.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    remember_me: bool = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class AuthSuccessResponse(BaseModel):
    success: bool = True
    message: str
    user: UserResponse
    token: Optional[str] = None


class MessageResponse(BaseModel):
    success: bool = True
    message: str

