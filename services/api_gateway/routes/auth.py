# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Authentication routes for login, logout, token refresh, and user info.

This version uses real database-backed users plus JWT access and refresh tokens.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from bcrypt import checkpw
from fastapi import APIRouter, Depends, Header, HTTPException, status
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.database.base import get_database_manager
from shared.database.models import User
from shared.utils import get_logger, utc_now
from shared.utils.config import get_config

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
config = get_config()


class LoginRequest(BaseModel):
    """Login request model."""

    username: str
    password: str


class TokenResponse(BaseModel):
    """Token response model."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None


class UserResponse(BaseModel):
    """User info response model."""

    id: str
    username: str
    email: Optional[str] = None
    role: str
    permissions: list[str] = []


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""

    refresh_token: str


ROLE_PERMISSIONS = {
    "admin": [
        "alerts:read",
        "alerts:write",
        "alerts:delete",
        "triage:read",
        "triage:write",
        "analytics:read",
        "workflows:read",
        "workflows:write",
        "settings:read",
        "settings:write",
        "reports:read",
        "reports:write",
        "users:read",
        "users:write",
    ],
    "operator": [
        "alerts:read",
        "alerts:write",
        "triage:read",
        "analytics:read",
        "workflows:read",
        "workflows:write",
        "reports:read",
    ],
    "analyst": [
        "alerts:read",
        "alerts:write",
        "triage:read",
        "triage:write",
        "analytics:read",
        "workflows:read",
        "reports:read",
    ],
    "viewer": [
        "alerts:read",
        "triage:read",
        "analytics:read",
        "workflows:read",
        "reports:read",
    ],
    "security_analyst": [
        "alerts:read",
        "alerts:write",
        "triage:read",
        "triage:write",
        "analytics:read",
        "workflows:read",
        "reports:read",
    ],
    "auditor": [
        "alerts:read",
        "triage:read",
        "analytics:read",
        "reports:read",
    ],
}


async def get_db_session() -> AsyncSession:
    """Get database session."""
    db_manager = get_database_manager()
    async with db_manager.get_session() as session:
        yield session


def build_permissions(role: str) -> list[str]:
    """Return permissions for role."""
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["viewer"])


def normalize_user_id(user_id: str):
    """Return UUID object when possible, otherwise keep original string."""
    try:
        return UUID(user_id)
    except Exception:
        return user_id


def create_access_token(user: User) -> tuple[str, int]:
    """Create signed JWT access token."""
    now = utc_now()
    expires_in = 24 * 60 * 60
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "permissions": build_permissions(user.role),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + expires_in,
    }
    token = jwt.encode(payload, config.jwt_secret_key, algorithm=config.jwt_algorithm)
    return token, expires_in


def create_refresh_token(user: User) -> str:
    """Create signed JWT refresh token."""
    now = utc_now()
    expires_in = 7 * 24 * 60 * 60
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + expires_in,
    }
    return jwt.encode(payload, config.jwt_secret_key, algorithm=config.jwt_algorithm)


def decode_token(token: str, token_type: str) -> dict:
    """Decode and validate token type."""
    try:
        payload = jwt.decode(
            token,
            config.jwt_secret_key,
            algorithms=[config.jwt_algorithm],
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        ) from exc

    if payload.get("type") != token_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    return payload


async def get_user_by_identity(session: AsyncSession, username: str) -> Optional[User]:
    """Look up active user by username or email."""
    result = await session.execute(
        select(User).where(
            (User.username == username) | (User.email == username),
            User.is_active.is_(True),
        )
    )
    return result.scalar_one_or_none()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify bcrypt password hash."""
    try:
        return checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


async def get_authenticated_user(
    authorization: Optional[str] = Header(default=None),
    session: AsyncSession = Depends(get_db_session),
) -> User:
    """Resolve current user from Authorization header."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )

    token = authorization.split(" ", 1)[1]
    payload = decode_token(token, "access")

    result = await session.execute(
        select(User).where(User.id == normalize_user_id(payload["sub"]), User.is_active.is_(True))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    session: AsyncSession = Depends(get_db_session),
):
    """Authenticate against database user records and return JWTs."""
    logger.info(f"Login attempt for user: {request.username}")

    user = await get_user_by_identity(session, request.username)
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user.last_login_at = utc_now()
    await session.commit()

    access_token, expires_in = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        refresh_token=refresh_token,
    )


@router.post("/logout")
async def logout():
    """Client-side logout placeholder."""
    logger.info("User logged out")
    return {"success": True, "message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    current_user: User = Depends(get_authenticated_user),
):
    """Return authenticated user details."""
    return UserResponse(
        id=str(current_user.id),
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        permissions=build_permissions(current_user.role),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    session: AsyncSession = Depends(get_db_session),
):
    """Refresh access token using a valid refresh token."""
    payload = decode_token(request.refresh_token, "refresh")

    result = await session.execute(
        select(User).where(User.id == normalize_user_id(payload["sub"]), User.is_active.is_(True))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    access_token, expires_in = create_access_token(user)
    refresh_token_value = create_refresh_token(user)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        refresh_token=refresh_token_value,
    )


def require_permissions(*permissions: str):
    """Dependency factory for permission checks."""

    async def check(current_user: User = Depends(get_authenticated_user)) -> User:
        user_permissions = set(build_permissions(current_user.role))
        missing = [perm for perm in permissions if perm not in user_permissions]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permissions: {', '.join(missing)}",
            )
        return current_user

    return check
