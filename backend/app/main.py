"""
FastAPI Main Application
LogGuard Backend - Real-time Log Monitoring System
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from app.api.v1.router import api_router
from app.controllers.websocket_controller import websocket_router

# Create FastAPI application
app = FastAPI(
    title="LogGuard API",
    description="Real-time Log Monitoring and Anomaly Detection API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix="/api")
app.include_router(websocket_router, prefix="/ws")

@app.get("/")
async def root():
    """Health check endpoint"""
    return {"message": "LogGuard API is running", "status": "healthy"}

@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "service": "LogGuard Backend",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
