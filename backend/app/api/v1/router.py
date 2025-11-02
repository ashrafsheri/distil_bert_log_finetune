"""
API v1 Router
Main router for API version 1 endpoints
"""

from fastapi import APIRouter

from app.controllers.log_controller import router as log_router
from app.controllers.user_controller import router as user_router

# Create main API router
api_router = APIRouter()

# Include sub-routers
api_router.include_router(log_router, prefix="/v1", tags=["logs"])
api_router.include_router(user_router, prefix="/v1/users", tags=["users"])
