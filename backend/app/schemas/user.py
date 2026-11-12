from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserResponse(BaseModel):
    id: str
    full_name: str
    email: EmailStr
    is_active: bool
    created_at: datetime
    role: str = "Security Analyst"
    organization: str = "Defense Operations"

    model_config = ConfigDict(from_attributes=True)
