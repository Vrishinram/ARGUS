from fastapi import APIRouter
from app.api.v1.admin import router as admin_router
from app.api.v1.chat import router as chat_router

api_router = APIRouter()

# Chat completion routes at /v1
api_router.include_router(chat_router, prefix="/v1")

# Admin telemetry routes at /api/v1
api_router.include_router(admin_router, prefix="/api/v1")
