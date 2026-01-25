"""
FastAPI Server for Real-time Log Anomaly Detection
Provides REST API endpoints for ensemble inference
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from models.ensemble_detector import EnsembleAnomalyDetector


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class LogRequest(BaseModel):
    """Single log line request"""
    log_line: str
    session_id: Optional[str] = None


class BatchLogRequest(BaseModel):
    """Batch of log lines"""
    log_lines: List[str]
    session_id: Optional[str] = None


class DetectionResponse(BaseModel):
    """Anomaly detection response"""
    is_anomaly: bool
    anomaly_score: float
    timestamp: str
    details: Dict


class BatchDetectionResponse(BaseModel):
    """Batch detection response"""
    results: List[DetectionResponse]
    total_logs: int
    anomalies_detected: int


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    model_loaded: bool
    vocab_size: int
    threshold: float


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Real-time Log Anomaly Detection API",
    description="Ensemble anomaly detection using Transformer + Rule-based + Isolation Forest",
    version="1.0.0"
)

# Global detector instance
detector: Optional[EnsembleAnomalyDetector] = None


@app.on_event("startup")
async def startup_event():
    """Initialize detector on startup"""
    global detector
    
    # Path to exported models
    repo_root = Path(__file__).parent.parent.parent
    model_dir = repo_root / 'artifacts/ensemble_model_export'
    
    if not model_dir.exists():

        logger.error(f"Model directory not found: {model_dir}")
        logger.error("Please run the model export notebook first (07_hybrid_attack_detection.ipynb)")
        return
    
    try:
        detector = EnsembleAnomalyDetector(
            model_dir=model_dir,
            window_size=20,
            device='cpu'  # Change to 'cuda' if GPU available
        )
        logger.info("Ensemble detector initialized successfully!")
    except Exception as e:
        logger.error(f"Failed to load models: {e}")
        raise


@app.get("/", response_model=Dict)
async def root():
    """Root endpoint"""
    return {
        "message": "Real-time Log Anomaly Detection API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "detect": "/detect (POST)",
            "detect_batch": "/detect/batch (POST)",
            "reset_session": "/reset/{session_id} (POST)"
        }
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    return HealthResponse(
        status="healthy",
        model_loaded=True,
        vocab_size=detector.vocab_size,
        threshold=detector.optimal_threshold
    )


@app.post("/detect", response_model=DetectionResponse)
async def detect_single(request: LogRequest):
    """
    Detect anomaly in a single log line
    
    Example:
    ```
    POST /detect
    {
        "log_line": "192.168.1.1 - - [22/Oct/2025:10:30:45 +0000] \"GET /admin' OR '1'='1 HTTP/1.1\" 403 1234",
        "session_id": "192.168.1.1"
    }
    ```
    """
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    try:
        result = detector.detect(request.log_line, request.session_id)
        
        return DetectionResponse(
            is_anomaly=result['is_anomaly'],
            anomaly_score=result['anomaly_score'],
            timestamp=datetime.now().isoformat(),
            details={
                'rule_based': result['rule_based'],
                'isolation_forest': result['isolation_forest'],
                'transformer': result['transformer'],
                'ensemble': result['ensemble'],
                'log_data': result['log_data']
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Detection failed: {str(e)}")


@app.post("/detect/batch", response_model=BatchDetectionResponse)
async def detect_batch(request: BatchLogRequest):
    """
    Detect anomalies in multiple log lines
    
    Example:
    ```
    POST /detect/batch
    {
        "log_lines": [
            "192.168.1.1 - - [22/Oct/2025:10:30:45 +0000] \"GET / HTTP/1.1\" 200 1234",
            "192.168.1.1 - - [22/Oct/2025:10:30:46 +0000] \"GET /admin HTTP/1.1\" 200 5678"
        ],
        "session_id": "192.168.1.1"
    }
    ```
    """
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    results = []
    anomaly_count = 0
    
    for log_line in request.log_lines:
        try:
            result = detector.detect(log_line, request.session_id)
            
            results.append(DetectionResponse(
                is_anomaly=result['is_anomaly'],
                anomaly_score=result['anomaly_score'],
                timestamp=datetime.now().isoformat(),
                details={
                    'rule_based': result['rule_based'],
                    'isolation_forest': result['isolation_forest'],
                    'transformer': result['transformer'],
                    'ensemble': result['ensemble'],
                    'log_data': result['log_data']
                }
            ))
            
            if result['is_anomaly']:
                anomaly_count += 1
                
        except Exception as e:
            # Log error but continue processing
            print(f"Error processing log: {e}")
            continue
    
    return BatchDetectionResponse(
        results=results,
        total_logs=len(results),
        anomalies_detected=anomaly_count
    )


@app.post("/reset/{session_id}")
async def reset_session(session_id: str):
    """Reset a specific session (clear history)"""
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    detector.reset_session(session_id)
    return {"message": f"Session '{session_id}' reset successfully"}


@app.post("/reset/all")
async def reset_all_sessions():
    """Reset all sessions"""
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    detector.reset_all_sessions()
    return {"message": "All sessions reset successfully"}


def main():
    """Run the API server"""
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()
