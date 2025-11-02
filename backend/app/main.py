"""
FastAPI Main Application
LogGuard Backend - Real-time Log Monitoring System
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn

from app.api.v1.router import api_router
from app.controllers.websocket_controller import router as websocket_router
from app.utils.database import init_db, close_db
from app.utils.firebase_auth import initialize_firebase_admin

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    # Startup: Initialize database and Firebase Admin SDK
    try:
        await init_db()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"⚠️  Database initialization warning: {e}")
    
    try:
        initialize_firebase_admin()
        print("✅ Firebase Admin SDK initialized successfully")
    except Exception as e:
        print(f"⚠️  Firebase Admin SDK initialization warning: {e}")
    
    yield
    
    # Shutdown: Close database connections
    try:
        await close_db()
        print("✅ Database connections closed")
    except Exception as e:
        print(f"⚠️  Database shutdown warning: {e}")


# Create FastAPI application
app = FastAPI(
    title="LogGuard API",
    description="Real-time Log Monitoring and Anomaly Detection API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
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
