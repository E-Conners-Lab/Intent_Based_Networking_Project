"""Shared dependencies for web routes."""

from fastapi import HTTPException, Request, status


def get_current_user(request: Request) -> str:
    """Dependency to get current authenticated user.

    Raises:
        HTTPException: If user is not authenticated
    """
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user


def require_auth(request: Request) -> str:
    """Dependency that requires authentication, redirects if not."""
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": "/login"},
        )
    return user
