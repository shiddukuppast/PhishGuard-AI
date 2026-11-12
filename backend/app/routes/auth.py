from fastapi import APIRouter, Depends, Request, Response, status
from app.config.settings import settings
from app.models.user import UserModel
from app.schemas.auth import (
    SignupRequest,
    LoginRequest,
    AuthSuccessResponse,
    MessageResponse,
)
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService
from app.utils.dependencies import get_current_user, limiter

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/signup",
    response_model=AuthSuccessResponse,
    status_code=status.HTTP_201_CREATED,
    summary="User Registration",
)
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def signup(request: Request, signup_data: SignupRequest, response: Response):
    """
    Register a new user account with Argon2 password hashing.
    Issues JWT access token and sets secure HTTP-only cookie.
    """
    user, token = await AuthService.signup_user(signup_data)
    AuthService.set_auth_cookie(response, token, remember_me=True)

    user_resp = UserResponse(
        id=user.id or "",
        full_name=user.full_name,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at,
    )

    return AuthSuccessResponse(
        success=True,
        message="Account created successfully.",
        user=user_resp,
        token=token,
    )


@router.post(
    "/login",
    response_model=AuthSuccessResponse,
    status_code=status.HTTP_200_OK,
    summary="User Login",
)
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def login(request: Request, login_data: LoginRequest, response: Response):
    """
    Authenticate user credentials using Argon2 verification.
    Generates JWT access token and sets secure HTTP-only session cookie.
    """
    user, token = await AuthService.login_user(login_data)
    AuthService.set_auth_cookie(response, token, remember_me=login_data.remember_me)

    user_resp = UserResponse(
        id=user.id or "",
        full_name=user.full_name,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at,
    )

    return AuthSuccessResponse(
        success=True,
        message="Authentication successful.",
        user=user_resp,
        token=token,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Current User Profile",
)
async def get_me(current_user: UserModel = Depends(get_current_user)):
    """Return profile details for the currently authenticated user."""
    return UserResponse(
        id=current_user.id or "",
        full_name=current_user.full_name,
        email=current_user.email,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="User Logout",
)
async def logout(response: Response):
    """Clear HTTP-only session cookie and terminate client session."""
    AuthService.clear_auth_cookie(response)
    return MessageResponse(
        success=True,
        message="Session successfully terminated.",
    )

