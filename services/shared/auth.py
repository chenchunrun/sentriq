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
Authentication and Authorization Module.

Provides JWT-based authentication and RBAC authorization for the system.
"""

import datetime
import os
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from cryptography.fernet import Fernet
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from shared.utils.logger import get_logger


logger = get_logger(__name__)


# =============================================================================
# Configuration
# =============================================================================

class AuthConfig:
    """Authentication configuration."""

    SECRET_KEY = os.getenv("JWT_SECRET_KEY", os.getenv("ENCRYPTION_KEY", ""))
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

    # Password hashing
    bcrypt_rounds = int(os.getenv("BCRYPT_ROUNDS", "12"))

    # Encryption for sensitive data
    encryption_key = os.getenv("ENCRYPTION_KEY", "").encode() if os.getenv("ENCRYPTION_KEY") else None
    fernet = Fernet(encryption_key) if encryption_key else None


# =============================================================================
# Models
# =============================================================================

class UserRole(str, Enum):
    """User roles with hierarchical permissions."""

    ADMIN = "admin"           # Full system access
    SECURITY_ANALYST = "security_analyst"  # Investigate and triage alerts
    OPERATOR = "operator"     # Day-to-day operations
    VIEWER = "viewer"         # Read-only access
    AUDITOR = "auditor"       # Audit log access only


class Permission(str, Enum):
    """Fine-grained permissions."""

    # Alert permissions
    ALERT_VIEW = "alert:view"
    ALERT_CREATE = "alert:create"
    ALERT_UPDATE = "alert:update"
    ALERT_DELETE = "alert:delete"
    ALERT_ASSIGN = "alert:assign"
    ALERT_CLOSE = "alert:close"

    # Triage permissions
    TRIAGE_VIEW = "triage:view"
    TRIAGE_EXECUTE = "triage:execute"
    TRIAGE_OVERRIDE = "triage:override"

    # Automation permissions
    AUTOMATION_VIEW = "automation:view"
    AUTOMATION_EXECUTE = "automation:execute"
    AUTOMATION_APPROVE = "automation:approve"

    # System permissions
    SYSTEM_CONFIG = "system:config"
    SYSTEM_USERS = "system:users"
    SYSTEM_MONITORING = "system:monitoring"
    SYSTEM_AUDIT = "system:audit"

    # Threat Intel permissions
    THREAT_INTEL_VIEW = "threat_intel:view"
    THREAT_INTEL_QUERY = "threat_intel:query"


# Role-Permission mapping
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: {perm for perm in Permission},  # All permissions

    UserRole.SECURITY_ANALYST: {
        Permission.ALERT_VIEW,
        Permission.ALERT_UPDATE,
        Permission.ALERT_ASSIGN,
        Permission.ALERT_CLOSE,
        Permission.TRIAGE_VIEW,
        Permission.TRIAGE_EXECUTE,
        Permission.AUTOMATION_VIEW,
        Permission.THREAT_INTEL_VIEW,
        Permission.THREAT_INTEL_QUERY,
    },

    UserRole.OPERATOR: {
        Permission.ALERT_VIEW,
        Permission.ALERT_CREATE,
        Permission.ALERT_UPDATE,
        Permission.AUTOMATION_VIEW,
        Permission.AUTOMATION_EXECUTE,
        Permission.THREAT_INTEL_VIEW,
        Permission.SYSTEM_MONITORING,
    },

    UserRole.VIEWER: {
        Permission.ALERT_VIEW,
        Permission.TRIAGE_VIEW,
        Permission.AUTOMATION_VIEW,
        Permission.THREAT_INTEL_VIEW,
    },

    UserRole.AUDITOR: {
        Permission.ALERT_VIEW,
        Permission.TRIAGE_VIEW,
        Permission.AUTOMATION_VIEW,
        Permission.SYSTEM_AUDIT,
    },
}


class TokenPayload(BaseModel):
    """JWT token payload."""

    sub: str = Field(..., description="User ID")
    email: EmailStr
    role: UserRole
    permissions: List[str]
    exp: Optional[int] = None
    iat: Optional[int] = None
    jti: Optional[str] = None  # Token ID for refresh token tracking


class TokenData(BaseModel):
    """Token response data."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "User"


class User(BaseModel):
    """User model."""

    id: str
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    role: UserRole
    permissions: Set[Permission]
    is_active: bool = True
    created_at: datetime.datetime
    updated_at: datetime.datetime
    last_login: Optional[datetime.datetime] = None


class LoginRequest(BaseModel):
    """Login request."""

    username_or_email: str
    password: str


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str


class UserCreate(BaseModel):
    """User creation request."""

    email: EmailStr
    username: str
    full_name: Optional[str] = None
    password: str
    role: UserRole = UserRole.VIEWER


class UserUpdate(BaseModel):
    """User update request."""

    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


# =============================================================================
# Authentication Functions
# =============================================================================

def hash_password(password: str) -> str:
    """
    Hash a password for storage.

    Args:
        password: Plain text password

    Returns:
        Hashed password
    """
    import bcrypt
    salt = bcrypt.gensalt(rounds=AuthConfig.bcrypt_rounds)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: Plain text password
        hashed_password: Hashed password

    Returns:
        True if password matches
    """
    import bcrypt
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False


def create_access_token(user: User) -> str:
    """
    Create JWT access token.

    Args:
        user: User object

    Returns:
        JWT token string
    """
    now = datetime.datetime.utcnow()
    expire = now + datetime.timedelta(minutes=AuthConfig.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = TokenPayload(
        sub=user.id,
        email=user.email,
        role=user.role,
        permissions=[perm.value for perm in user.permissions],
        exp=int(expire.timestamp()),
        iat=int(now.timestamp()),
    )

    # Encode JWT
    token = jwt.encode(
        payload.model_dump(exclude_none=True),
        AuthConfig.SECRET_KEY,
        algorithm=AuthConfig.ALGORITHM,
    )

    return token


def create_refresh_token(user: User) -> str:
    """
    Create JWT refresh token (longer expiry).

    Args:
        user: User object

    Returns:
        Refresh token string
    """
    now = datetime.datetime.utcnow()
    expire = now + datetime.timedelta(days=AuthConfig.REFRESH_TOKEN_EXPIRE_DAYS)

    payload = {
        "sub": user.id,
        "exp": int(expire.timestamp()),
        "type": "refresh",
    }

    token = jwt.encode(
        payload,
        AuthConfig.SECRET_KEY,
        algorithm=AuthConfig.ALGORITHM,
    )

    return token


def decode_token(token: str) -> Optional[TokenPayload]:
    """
    Decode and validate JWT token.

    Args:
        token: JWT token string

    Returns:
        Token payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            AuthConfig.SECRET_KEY,
            algorithms=[AuthConfig.ALGORITHM],
        )

        return TokenPayload(**payload)

    except JWTError as e:
        logger.warning(f"Invalid token: {e}")
        return None


def encrypt_sensitive_data(data: str) -> str:
    """
    Encrypt sensitive data for storage.

    Args:
        data: Plain text data

    Returns:
        Encrypted data (Fernet token)
    """
    if not AuthConfig.fernet:
        raise ValueError("Encryption not configured")

    encrypted = AuthConfig.fernet.encrypt(data.encode())
    return encrypted.decode()


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """
    Decrypt sensitive data.

    Args:
        encrypted_data: Encrypted data

    Returns:
        Plain text data
    """
    if not AuthConfig.fernet:
        raise ValueError("Encryption not configured")

    decrypted = AuthConfig.fernet.decrypt(encrypted_data.encode())
    return decrypted.decode()


# =============================================================================
# Authorization Functions
# =============================================================================

def get_user_permissions(user_role: UserRole) -> Set[Permission]:
    """
    Get permissions for a user role.

    Args:
        user_role: User's role

    Returns:
        Set of permissions
    """
    return ROLE_PERMISSIONS.get(user_role, set())


def has_permission(user: User, permission: Permission) -> bool:
    """
    Check if user has a specific permission.

    Args:
        user: User object
        permission: Permission to check

    Returns:
        True if user has permission
    """
    # Admin has all permissions
    if user.role == UserRole.ADMIN:
        return True

    return permission in user.permissions


def has_any_permission(user: User, permissions: List[Permission]) -> bool:
    """
    Check if user has any of the specified permissions.

    Args:
        user: User object
        permissions: List of permissions to check

    Returns:
        True if user has any permission
    """
    return any(has_permission(user, perm) for perm in permissions)


def has_all_permissions(user: User, permissions: List[Permission]) -> bool:
    """
    Check if user has all of the specified permissions.

    Args:
        user: User object
        permissions: List of permissions to check

    Returns:
        True if user has all permissions
    """
    return all(has_permission(user, perm) for perm in permissions)


# =============================================================================
# JWT Dependencies for FastAPI
# =============================================================================

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    """
    Get current user from JWT token.

    Args:
        credentials: HTTP Bearer credentials

    Returns:
        Current user

    Raises:
        HTTPException: If token is invalid
    """
    token = credentials.credentials
    payload = decode_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # TODO: Fetch user from database
    # For now, create user from token payload
    user = User(
        id=payload.sub,
        email=payload.email,
        username=payload.email.split("@")[0],
        role=payload.role,
        permissions={perm for perm in Permission if perm.value in payload.permissions},
        is_active=True,
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow(),
    )

    return user


async def require_permission(required_permission: Permission):
    """
    Dependency factory to require a specific permission.

    Args:
        required_permission: Required permission

    Returns:
        Dependency function
    """
    async def check_permission(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user, required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {required_permission.value}",
            )
        return current_user

    return check_permission


async def require_any_permission(*required_permissions: Permission):
    """
    Dependency factory to require any of the specified permissions.

    Args:
        *required_permissions: Required permissions

    Returns:
        Dependency function
    """
    async def check_permissions(current_user: User = Depends(get_current_user)) -> User:
        if not has_any_permission(current_user, list(required_permissions)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of these permissions required: {[p.value for p in required_permissions]}",
            )
        return current_user

    return check_permissions


async def require_role(*roles: UserRole):
    """
    Dependency factory to require a specific role.

    Args:
        *roles: Required roles

    Returns:
        Dependency function
    """
    async def check_role(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of these roles required: {[r.value for r in roles]}",
            )
        return current_user

    return check_role


# =============================================================================
# Admin User Creation
# =============================================================================

def create_admin_user() -> User:
    """
    Create initial admin user for first-time setup.

    Returns:
        Created admin user
    """
    admin_password = os.getenv("INITIAL_ADMIN_PASSWORD", "admin123")

    user = User(
        id="admin",
        email="admin@security-triage.local",
        username="admin",
        full_name="Security Administrator",
        role=UserRole.ADMIN,
        permissions=set(Permission),  # All permissions
        is_active=True,
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow(),
    )

    logger.warning("Initial admin user created. Please change the password immediately!")
    logger.info(f"Admin credentials: admin / {admin_password}")

    return user


# =============================================================================
# Audit Logging
# =============================================================================

class AuditAction(str, Enum):
    """Audit action types."""

    LOGIN = "login"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    PASSWORD_CHANGE = "password_change"
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_DELETE = "user_delete"
    ROLE_CHANGE = "role_change"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    ALERT_VIEW = "alert_view"
    ALERT_UPDATE = "alert_update"
    ALERT_DELETE = "alert_delete"
    TRIAGE_EXECUTE = "triage_execute"
    AUTOMATION_EXECUTE = "automation_execute"
    CONFIG_CHANGE = "config_change"


def log_audit_event(
    action: AuditAction,
    user_id: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    success: bool = True,
    error_message: Optional[str] = None,
):
    """
    Log an audit event.

    Args:
        action: Action performed
        user_id: User who performed the action
        resource_type: Type of resource affected
        resource_id: ID of resource affected
        details: Additional details
        ip_address: Client IP address
        user_agent: Client user agent
        success: Whether action was successful
        error_message: Error message if unsuccessful
    """
    logger.info(
        "Audit Event",
        extra={
            "audit": True,
            "action": action.value,
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": success,
            "error_message": error_message,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        },
    )
