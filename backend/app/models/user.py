from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from bson import ObjectId


class PyObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, info=None):
        if isinstance(v, ObjectId):
            return str(v)
        if isinstance(v, str) and ObjectId.is_valid(v):
            return str(v)
        raise ValueError("Invalid ObjectId")


class UserModel(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    full_name: str
    email: EmailStr
    hashed_password: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
