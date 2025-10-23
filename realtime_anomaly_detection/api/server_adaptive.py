"""
FastAPI Server for Adaptive Real-time Log Anomaly Detection
Uses online learning: Rule-based + Iso Forest initially, trains Transformer on first N logs
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

from models.adaptive_detector import AdaptiveEnsembleDetector


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
    phase: str  # warmup, training, or ensemble
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
    phase: str
    logs_processed: int
    transformer_ready: bool
    active_models: int


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Adaptive Real-time Log Anomaly Detection API",
    description="Online learning ensemble: trains Transformer on first 50k logs",
    version="2.0.0"
)

# Global detector instance
detector: Optional[AdaptiveEnsembleDetector] = None


@app.on_event("startup")
async def startup_event():
    """Initialize adaptive detector on startup"""
    global detector
    
    # Path to exported models - use environment variable if set, otherwise use relative path
    import os
    model_dir = Path(os.getenv('MODEL_DIR', '/app/artifacts/ensemble_model_export'))
    
    if not model_dir.exists():
        print(f"❌ Model directory not found: {model_dir}")
        print("Please run the model export notebook first (07_hybrid_attack_detection.ipynb)")
        return
    
    try:
        detector = AdaptiveEnsembleDetector(
            model_dir=model_dir,
            warmup_logs=50000,  # Train on first 50k logs
            window_size=20,
            device='cpu'  # Change to 'cuda' if GPU available
        )
        print("✓ Adaptive detector initialized successfully!")
    except Exception as e:
        print(f"❌ Failed to load models: {e}")
        raise


@app.get("/", response_model=Dict)
async def root():
    """Root endpoint"""
    return {
        "message": "Adaptive Real-time Log Anomaly Detection API",
        "version": "2.0.0",
        "learning_mode": "online",
        "endpoints": {
            "health": "/health",
            "detect": "/detect (POST)",
            "detect_batch": "/detect/batch (POST)",
            "status": "/status"
        }
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    if detector.logs_processed < detector.warmup_logs:
        phase = "warmup"
    elif detector.training_in_progress:
        phase = "training"
    elif detector.transformer_ready:
        phase = "ensemble"
    else:
        phase = "waiting"
    
    # Count active models
    active_models = 1  # Rule-based always active
    if detector.iso_forest_ready:
        active_models += 1
    if detector.transformer_ready:
        active_models += 1
    
    return HealthResponse(
        status="healthy",
        phase=phase,
        logs_processed=detector.logs_processed,
        transformer_ready=detector.transformer_ready,
        active_models=active_models
    )


@app.get("/status", response_model=Dict)
async def get_status():
    """Get detailed status"""
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    return {
        "logs_processed": detector.logs_processed,
        "warmup_target": detector.warmup_logs,
        "warmup_complete": detector.logs_processed >= detector.warmup_logs,
        "training_in_progress": detector.training_in_progress,
        "isolation_forest_ready": detector.iso_forest_ready,
        "transformer_ready": detector.transformer_ready,
        "vocabulary_size": len(detector.id_to_template),
        "training_sequences": len(detector.training_templates),
        "iso_training_samples": len(detector.iso_training_features),
        "active_models": {
            "rule_based": True,
            "isolation_forest": detector.iso_forest_ready,
            "transformer": detector.transformer_ready
        },
        "phase": "warmup" if detector.logs_processed < detector.warmup_logs else (
            "training" if detector.training_in_progress else "ensemble"
        )
    }


@app.post("/detect", response_model=DetectionResponse)
async def detect_single(request: LogRequest):
    """
    Detect anomaly in a single log line
    Adapts over time: trains transformer on first 50k logs
    """
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    try:
        result = detector.detect(request.log_line, request.session_id)
        
        return DetectionResponse(
            is_anomaly=result['is_anomaly'],
            anomaly_score=result['anomaly_score'],
            phase=result['phase'],
            timestamp=datetime.now().isoformat(),
            details={
                'logs_processed': result['logs_processed'],
                'transformer_ready': result['transformer_ready'],
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
                phase=result['phase'],
                timestamp=datetime.now().isoformat(),
                details={
                    'logs_processed': result['logs_processed'],
                    'transformer_ready': result['transformer_ready'],
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
            print(f"Error processing log: {e}")
            continue
    
    return BatchDetectionResponse(
        results=results,
        total_logs=len(results),
        anomalies_detected=anomaly_count
    )


def main():
    """Run the API server"""
    uvicorn.run(
        "server_adaptive:app",
        host="0.0.0.0",
        port=8000,
        reload=False,  # Disable reload for background training
        log_level="info"
    )


if __name__ == "__main__":
    main()
