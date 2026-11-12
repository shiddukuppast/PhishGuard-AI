import logging
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional
from fastapi import Response, HTTPException, status
from bson import ObjectId
from pymongo.errors import PyMongoError
from app.config.settings import settings
from app.config.database import get_db
from app.models.user import UserModel
from app.schemas.auth import SignupRequest, LoginRequest
from app.utils.security import hash_password, verify_password, create_access_token

logger = logging.getLogger("phishguard.auth")


class AuthService:
    @staticmethod
    async def signup_user(signup_data: SignupRequest) -> Tuple[UserModel, str]:
        """Register a new user and generate access token."""
        db = get_db()
        if db is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable. Please try again later.",
            )

        normalized_email = signup_data.email.strip().lower()

        # Check for existing email with database error isolation
        try:
            existing_user = await db.users.find_one({"email": normalized_email})
        except PyMongoError as exc:
            logger.error("Database query failed during signup check: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable. Please try again later.",
            )

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email address already exists.",
            )

        # Hash password with Argon2
        hashed_pwd = hash_password(signup_data.password)

        now = datetime.now(timezone.utc)
        user_dict = {
            "full_name": signup_data.full_name,
            "email": normalized_email,
            "hashed_password": hashed_pwd,
            "created_at": now,
            "updated_at": now,
            "is_active": True,
        }

        try:
            result = await db.users.insert_one(user_dict)
        except PyMongoError as exc:
            logger.error("Database insert failed during signup: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable. Please try again later.",
            )

        user_id_str = str(result.inserted_id)
        user_dict["_id"] = user_id_str

        # Create JWT token
        token = create_access_token(data={"sub": user_id_str, "email": normalized_email})

        user_model = UserModel(**user_dict)
        return user_model, token

    @staticmethod
    async def login_user(login_data: LoginRequest) -> Tuple[UserModel, str]:
        """Authenticate user with email and password, returning user model and JWT."""
        db = get_db()
        if db is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable. Please try again later.",
            )

        normalized_email = login_data.email.strip().lower()

        try:
            user_doc = await db.users.find_one({"email": normalized_email})
        except PyMongoError as exc:
            logger.error("Database query failed during user login: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service is unavailable. Please try again later.",
            )

        if not user_doc or not verify_password(login_data.password, user_doc.get("hashed_password", "")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user_doc.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This user account has been deactivated.",
            )

        user_id_str = str(user_doc["_id"])
        user_doc["_id"] = user_id_str

        # Calculate token expiration (longer if remember_me is true)
        expires_delta = timedelta(days=30) if login_data.remember_me else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token = create_access_token(data={"sub": user_id_str, "email": normalized_email}, expires_delta=expires_delta)

        user_model = UserModel(**user_doc)
        return user_model, token

    @staticmethod
    def set_auth_cookie(response: Response, token: str, remember_me: bool = True) -> None:
        """Set HTTP-only secure cookie for browser session."""
        max_age = 60 * 60 * 24 * 30 if remember_me else 60 * settings.ACCESS_TOKEN_EXPIRE_MINUTES
        response.set_cookie(
            key=settings.COOKIE_NAME,
            value=token,
            max_age=max_age,
            expires=max_age,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
            domain=settings.COOKIE_DOMAIN,
            path="/",
        )

    @staticmethod
    def clear_auth_cookie(response: Response) -> None:
        """Clear HTTP-only session cookie."""
        response.delete_cookie(
            key=settings.COOKIE_NAME,
            path="/",
            domain=settings.COOKIE_DOMAIN,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
        )

