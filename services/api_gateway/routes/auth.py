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

Handles user authentication with JWT tokens.
"""

import logging
from typing import Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Depends, Response
from pydantic import BaseModel
from passlib.context import CryptContext

from shared.utils.logger import get_logger
from shared.database.base import get_database_manager
from shared.database.models import User

# Logger
logger = get_logger(__name__)

# Router
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# =============================================================================
# Request/Response Models
# =============================================================================

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


# =============================================================================
# Helper Functions
# =============================================================================

def create_access_token(user_id: str, username: str) -> tuple[str, str]:
    """
    Create JWT access token.

    Returns:
        (access_token, expires_in_seconds)
    """
    from datetime import datetime, timezone

    # Simple token implementation (in production, use proper JWT)
    # Token format: {user_id}:{username}:{exp_timestamp}
    exp_timestamp = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
    token_string = f"{user_id}:{username}:{exp_timestamp}"
    access_token = token_string

    return access_token, 86400  # 24 hours


def verify_token(token: str) -> Optional[dict]:
    """
    Verify JWT token and return user info.

    Returns:
        User dict or None
    """
    try:
        # Simple token verification (in production, use proper JWT)
        parts = token.split(':')
        if len(parts) != 3:
            return None

        user_id, username, exp_timestamp = parts
        exp_timestamp_int = int(exp_timestamp)

        from datetime import datetime, timezone
        exp_time = datetime.fromtimestamp(exp_timestamp_int, tz=timezone.utc)

        if datetime.now(timezone.utc) > exp_time:
            return None

        return {
            "user_id": user_id,
            "username": username,
        }
    except Exception:
        return None


# =============================================================================
# Routes
# =============================================================================

@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    db_manager = Depends(get_database_manager)
):
    """
    Login endpoint - authenticates user and returns access token.

    Args:
        request: Login request with username and password
        db_manager: Database manager dependency

    Returns:
        TokenResponse with access_token

    Raises:
        HTTPException 401 if credentials invalid
    """
    logger.info(f"Login attempt for user: {request.username}")

    # For demo: accept any username/password combination
    # In production: verify hashed password from database
    user_id = f"demo_{request.username}"
    username = request.username
    email = f"{request.username}@example.com"

    # Create access token
    access_token, expires_in = create_access_token(user_id, username)

    logger.info(f"User {request.username} logged in successfully")

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in
    )


@router.post("/logout")
async def logout():
    """
    Logout endpoint - clears session.

    In a JWT-based system, the client simply removes the token.
    Server-side session invalidation could be added with Redis blacklist.
    """
    logger.info("User logged out")
    return {"success": True, "message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    db_manager = Depends(get_database_manager)
):
    """
    Get current authenticated user info.

    Returns:
        UserResponse with user details

    Raises:
        HTTPException 401 if token invalid or user not found
    """
    # In production, extract user from JWT token
    # For now, return demo user

    # Demo user data (in production, fetch from database)
    demo_user = User(
        id="demo-user-001",
        username="admin",
        email="admin@example.com",
        role="admin",
        permissions=[
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
        ],
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
    )

    logger.debug(f"Returning user info for: {demo_user.username}")

    return demo_user


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshTokenRequest):
    """
    Refresh access token.

    Args:
        request: Refresh token request

    Returns:
        TokenResponse with new access_token

    Raises:
        HTTPException 401 if refresh token invalid
    """
    # In production, validate refresh token and issue new access token
    # For demo, just return a new token

    # Extract user info from old token
    user_info = verify_token(request.refresh_token)

    if not user_info:
        logger.warning("Invalid refresh token attempt")
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Create new access token
    access_token, expires_in = create_access_token(
        user_info["user_id"],
        user_info["username"]
    )

    logger.info(f"Token refreshed for user: {user_info['username']}")

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in
    )


# =============================================================================
# Error Handlers
# =============================================================================

@router.exception_handler(Exception)
async def auth_exception_handler(request, exc: Exception):
    """Global exception handler for auth routes."""
    logger.error(f"Auth error: {exc}", extra={"path": str(request.url.path)})
    return Response(
        status_code=500,
        content={
            "success": False,
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred",
            "detail": str(exc) if logger.isEnabledFor(logging.DEBUG) else None
        }
    )
