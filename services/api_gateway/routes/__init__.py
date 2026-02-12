"""API Routes Package."""
from fastapi import APIRouter

__all__ = ["router"]

# Import auth router to ensure it's loaded
try:
    import routes.auth
except ImportError:
    pass
