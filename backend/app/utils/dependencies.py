import logging
from typing import Optional
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from bson import ObjectId
from pymongo.errors import PyMongoError
from app.config.settings import settings
from app.config.database import get_db
from app.models.user import UserModel
from app.utils.security import decode_access_token
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger("phishguard.auth")

# Rate Limiter instance based on client IP
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"] if settings.RATE_LIMIT_ENABLED else [])

# Optional bearer scheme for swagger docs & API clients
bearer_scheme = HTTPBearer(auto_error=False)


async def get_token_from_request(
    request: Request,
    bearer_auth: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[str]:
    """
    Extract token from:
    1. Authorization Bearer header
    2. HTTP-only session cookie (phishguard_access_token)
    """
    # 1. Bearer header
    if bearer_auth and bearer_auth.credentials:
        return bearer_auth.credentials

    # 2. Cookie
    token = request.cookies.get(settings.COOKIE_NAME)
    if token:
        return token

    return None


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(get_token_from_request),
) -> UserModel:
    """
    Dependency that enforces authentication.
    Raises 401 if token is missing, expired, or invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or session has expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        logger.warning(
            "Authentication failed on %s %s: No token found. Cookies present: %s, Authorization header present: %s",
            request.method,
            request.url.path,
            list(request.cookies.keys()),
            "Authorization" in request.headers or "authorization" in request.headers,
        )
        raise credentials_exception

    payload = decode_access_token(token)
    if payload is None:
        logger.warning(
            "Authentication failed on %s %s: Token decode failed (token expired or secret signature mismatch).",
            request.method,
            request.url.path,
        )
        raise credentials_exception

    user_id: Optional[str] = payload.get("sub")
    if user_id is None:
        logger.warning("Authentication failed: No 'sub' field in token payload.")
        raise credentials_exception

    db = get_db()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection is unavailable.",
        )

    try:
        obj_id = ObjectId(user_id)
    except Exception:
        logger.warning("Authentication failed: Invalid user ID format '%s'.", user_id)
        raise credentials_exception

    try:
        user_doc = await db.users.find_one({"_id": obj_id})
    except PyMongoError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection is unavailable.",
        )

    if user_doc is None:
        logger.warning(
            "Authentication failed: User '%s' does not exist in the database.",
            user_id,
        )
        raise credentials_exception

    if not user_doc.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    # Convert MongoDB _id to string for Pydantic model
    user_doc["_id"] = str(user_doc["_id"])
    return UserModel(**user_doc)


async def get_optional_current_user(
    request: Request,
    token: Optional[str] = Depends(get_token_from_request),
) -> Optional[UserModel]:
    """
    Dependency that returns the current user if authenticated, or None if guest.
    Allows on-demand scans to execute for unauthenticated visitors while tagging authenticated scans with user_id.
    """
    if not token:
        return None

    try:
        return await get_current_user(request=request, token=token)
    except HTTPException:
        return None

