import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
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

# CORS middleware for client & dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


# Web UI Dashboard Route (No Streamlit - Fast, Native, Dark Glassmorphic SOC)
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for Kubernetes / Docker / load balancers."""
    return {
        "status": "healthy",
        "gateway": "ARGUS AI Defense Gateway",
        "version": "1.0.0",
        "upstream_provider": settings.ARGUS_UPSTREAM_PROVIDER,
        "database": "sqlite_wal_active",
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
