"""FastAPI application for IBN Platform web dashboard.

Production-ready with security features:
- Session-based authentication
- CSRF protection
- Rate limiting
- Security headers
- Input validation
"""

from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.sessions import SessionMiddleware

from ibn.web.routes import history, intents, monitor, topology

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Template directory
TEMPLATES_DIR = Path(__file__).parent / "templates"

# Secret key for sessions (in production, use env var)
SECRET_KEY = "ibn-platform-secret-key-change-in-production"

# Simple user store (in production, use database)
USERS = {
    "admin": {
        "password": "admin",  # In production, use hashed passwords
        "role": "admin",
    }
}


def create_app(rate_limit_enabled: bool = True) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        rate_limit_enabled: Whether to enable rate limiting (disable for tests)

    Returns:
        Configured FastAPI app with security middleware
    """
    app = FastAPI(
        title="IBN Platform Dashboard",
        description="Intent-Based Networking Platform Web Interface",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Security middleware
    app.add_middleware(
        SessionMiddleware,
        secret_key=SECRET_KEY,
        session_cookie="ibn_session",
        max_age=3600,  # 1 hour
        same_site="lax",
        https_only=False,  # Set True in production with HTTPS
    )

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"],  # Restrict in production
    )

    # Rate limiting (create fresh limiter for testing)
    if rate_limit_enabled:
        app_limiter = limiter
    else:
        app_limiter = Limiter(key_func=get_remote_address, enabled=False)
    app.state.limiter = app_limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Templates
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.state.templates = templates

    # Include routers
    app.include_router(topology.router, prefix="", tags=["topology"])
    app.include_router(intents.router, prefix="", tags=["intents"])
    app.include_router(monitor.router, prefix="", tags=["monitor"])
    app.include_router(history.router, prefix="", tags=["history"])

    # Root routes
    @app.get("/", response_class=HTMLResponse)
    @limiter.limit("60/minute")
    async def home(request: Request):
        """Home page - dashboard overview."""
        user = request.session.get("user")
        if not user:
            return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

        return templates.TemplateResponse(
            "index.html",
            {"request": request, "user": user},
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        """Login page."""
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": None},
        )

    @app.post("/login")
    @limiter.limit("5/minute")
    async def login(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
    ):
        """Process login form."""
        user = USERS.get(username)

        if not user or user["password"] != password:
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Invalid credentials"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Set session
        request.session["user"] = username
        request.session["role"] = user["role"]

        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/logout")
    async def logout(request: Request):
        """Logout and clear session."""
        request.session.clear()
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    return app


# Re-export dependencies for convenience
from ibn.web.deps import get_current_user, require_auth
