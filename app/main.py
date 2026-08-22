import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.api.v1.router import api_router
from app.config import settings
from app.core.errors import (
    RateLimitExceededException,
    SecurityPolicyViolationException,
    UnauthorizedException,
    UpstreamProviderException,
    rate_limit_handler,
    security_policy_violation_handler,
    unauthorized_handler,
    upstream_provider_handler,
)
from app.policy.engine import PolicyEngine
from app.storage.database import db_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.ARGUS_DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("argus.gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize async SQLite tables and indexes
    logger.info("Initializing ARGUS Security Gateway database...")
    await db_manager.init_db()
    logger.info("Database initialized successfully.")
    yield
    # Shutdown
    logger.info("ARGUS Security Gateway shutting down.")


app = FastAPI(
    title="ARGUS // LLM Security Gateway",
    description="Production-grade AI safety proxy, multi-vector prompt inspector, and real-time defense gateway.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware with restricted origins from settings (NEVER wildcard in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Argus-Client-Key", "X-API-Key", "X-Argus-Admin-Key"],
)

# Add Rate-Limit / Security headers middleware
@app.middleware("http")
async def add_security_and_rate_limit_headers(request: Request, call_next):
    response: Response = await call_next(request)
    if settings.ARGUS_RATE_LIMIT_ENABLED:
        response.headers["X-RateLimit-Limit"] = str(settings.ARGUS_RATE_LIMIT_REQUESTS_PER_MINUTE)
        response.headers["X-RateLimit-Period"] = "60s"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# Register Custom Security Exception Handlers
app.add_exception_handler(SecurityPolicyViolationException, security_policy_violation_handler)
app.add_exception_handler(RateLimitExceededException, rate_limit_handler)
app.add_exception_handler(UnauthorizedException, unauthorized_handler)
app.add_exception_handler(UpstreamProviderException, upstream_provider_handler)

# Mount Static Assets & Templates
BASE_DIR = Path(__file__).resolve().parent
static_dir = BASE_DIR / "static"
templates_dir = BASE_DIR / "templates"

if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

templates = Jinja2Templates(directory=str(templates_dir))


# Web UI Dashboard Route (Fast, Native, Dark Glassmorphic SOC)
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard(request: Request):
    if settings.ARGUS_ADMIN_API_KEY:
        admin_key = (
            request.query_params.get("key")
            or request.headers.get("X-Argus-Admin-Key")
            or (request.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            or request.cookies.get("argus_admin_key")
        )
        if admin_key != settings.ARGUS_ADMIN_API_KEY:
            return JSONResponse(
                {
                    "error": "unauthorized",
                    "message": "Valid ARGUS_ADMIN_API_KEY required via ?key= query parameter, X-Argus-Admin-Key header, or Bearer token.",
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint verifying gateway status, policy file parsing, and SQLite DB connectivity."""
    policy_path = settings.policy_full_path
    policy_loaded = False
    policy_name = "unknown"
    policy_error = None

    if policy_path.exists():
        try:
            engine = PolicyEngine(policy_path)
            policy_loaded = engine.policy is not None
            policy_name = getattr(engine.policy.metadata, "name", "Default Policy")
        except Exception as e:
            policy_error = str(e)

    db_reachable = await db_manager.check_health()
    status_str = "healthy" if (policy_loaded and db_reachable) else "degraded"

    return {
        "status": status_str,
        "gateway": "ARGUS AI Defense Gateway",
        "version": "1.0.0",
        "upstream_provider": settings.ARGUS_UPSTREAM_PROVIDER,
        "policy": {
            "path": str(policy_path),
            "loaded": policy_loaded,
            "name": policy_name,
            "error": policy_error,
        },
        "database": {
            "path": str(settings.db_full_path),
            "reachable": db_reachable,
        },
        "rate_limit_enabled": settings.ARGUS_RATE_LIMIT_ENABLED,
    }


# Mount Chat and Admin Routers
app.include_router(api_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.ARGUS_HOST,
        port=settings.ARGUS_PORT,
        reload=settings.ARGUS_DEBUG,
    )
