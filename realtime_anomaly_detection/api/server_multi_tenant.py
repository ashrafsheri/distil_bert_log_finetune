"""
FastAPI Server for Multi-Tenant Log Anomaly Detection
Provides REST API endpoints with API key authentication for multi-project SaaS deployment.

Features:
- Project management (create, list, delete)
- API key authentication per project
- Automatic student model training after warmup
- Periodic teacher model updates
"""

import sys
import os
from pathlib import Path
from typing import Annotated, Dict, List, Optional, Any
from datetime import datetime
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, Header, Depends, Query, BackgroundTasks
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, ConfigDict
import uvicorn

from models.multi_tenant_detector import MultiTenantDetector
from models.knowledge_distillation import TeacherUpdateScheduler
from models.runtime_metrics import runtime_metrics


logger = logging.getLogger(__name__)
# Deployment note: keep a touched source line here for workflow-trigger commits when
# image rebuilds are needed without changing detector behavior.


# ============================================================================
# CONSTANTS
# ============================================================================

ERROR_DETECTOR_NOT_INITIALIZED = "Detector not initialized"
ERROR_INVALID_API_KEY = "Invalid API key"
ERROR_ADMIN_ACCESS_REQUIRED = "Admin access required"
ADMIN_API_KEY_DESCRIPTION = "Admin API key"


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class CreateProjectRequest(BaseModel):
    """Request to create a new project"""
    project_name: str = Field(..., description="Human-readable project name")
    warmup_threshold: Optional[int] = Field(
        10000, 
        description="Number of logs before student model training"
    )
    metadata: Optional[Dict] = Field(None, description="Optional metadata")


class CreateProjectResponse(BaseModel):
    """Response after creating a project"""
    project_id: str
    project_name: str
    api_key: str = Field(
        ..., 
        description="API key for this project. Store securely - shown only once!"
    )
    warmup_threshold: int
    es_index_pattern: str


class ProjectStatusResponse(BaseModel):
    """Project status response"""
    project_id: str
    project_name: str
    phase: str
    log_count: int
    warmup_threshold: int
    warmup_progress: float
    has_student_model: bool
    traffic_profile: str = "standard"
    low_sample_calibration: bool = False
    created_at: str
    last_activity: str


class LogRequest(BaseModel):
    """Single log line request"""
    log_line: str
    session_id: Optional[str] = None


class BatchLogRequest(BaseModel):
    """Batch of log lines"""
    log_lines: List[str]
    session_id: Optional[str] = None


class StructuredLogRequest(BaseModel):
    project_id: str
    project_name: str
    warmup_threshold: Optional[int] = None
    session_key: str
    log_type: str
    event_time: Optional[str] = None
    normalized_event: Optional[str] = None
    raw_log: str
    parsed_fields: Dict[str, Any]
    traffic_class: Optional[str] = None
    flags: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class StructuredBatchLogRequest(BaseModel):
    events: List[StructuredLogRequest]


class InternalProjectRequest(BaseModel):
    project_id: str
    project_name: str
    warmup_threshold: Optional[int] = 10000
    traffic_profile: Optional[str] = "standard"
    metadata: Optional[Dict[str, Any]] = None


class ProjectIngestStatsRequest(BaseModel):
    project_id: str
    total_records: int
    parse_failures: int = 0
    baseline_eligible: int = 0
    clean_baseline_count: int = 0
    dirty_excluded_count: int = 0
    probe_skipped_count: int = 0
    distinct_template_count: int = 0
    observed_hours: List[int] = Field(default_factory=list)
    data_quality_incident_open: Optional[bool] = None
    traffic_profile: Optional[str] = None


class DetectionResponse(BaseModel):
    """Anomaly detection response"""
    model_config = ConfigDict(protected_namespaces=())

    is_anomaly: bool
    anomaly_score: float
    model_type: str  # 'teacher' or 'student'
    phase: str  # 'warmup', 'training', or 'active'
    project_id: str
    project_name: str
    log_count: int
    warmup_progress: float
    timestamp: str
    details: Dict


class BatchDetectionResponse(BaseModel):
    """Batch detection response"""
    results: List[DetectionResponse]
    total_logs: int
    anomalies_detected: int
    project_id: str


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    teacher_loaded: bool
    total_projects: int
    active_student_models: int
    training_in_progress: int


class TeacherInfoResponse(BaseModel):
    """Teacher model information"""
    vocab_size: int
    num_templates: int
    transformer_threshold: float
    total_logs_processed: int
    is_training: bool


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Multi-Tenant Log Anomaly Detection API",
    description="""
    SaaS API for log anomaly detection with student-teacher architecture.
    
    ## Features
    - **Multi-project support** with unique API keys
    - **Automatic model training** after warmup period
    - **Project-specific models** for better accuracy
    - **Periodic teacher updates** from aggregated project data
    
    ## Workflow
    1. Create a project and get API key
    2. Send logs during warmup (uses teacher model)
    3. After warmup, student model is automatically trained
    4. Active phase uses project-specific student model
    """,
    version="3.0.1"
)

# API Key security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Global detector instance
detector: Optional[MultiTenantDetector] = None
update_scheduler: Optional[TeacherUpdateScheduler] = None


# ============================================================================
# DEPENDENCIES
# ============================================================================

def get_project_from_api_key(
    api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> str:
    """Validate API key and return project ID"""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
    
    if not api_key:
        raise HTTPException(
            status_code=401, 
            detail="API key required. Pass X-API-Key header."
        )
    
    project_id = detector.validate_api_key(api_key)
    if not project_id:
        raise HTTPException(status_code=401, detail=ERROR_INVALID_API_KEY)
    
    return project_id


def validate_admin_key(admin_key: Optional[str] = None) -> bool:
    """
    Validate admin API key.
    
    Returns True if:
    - No ADMIN_API_KEY is configured (development mode)
    - The provided key matches ADMIN_API_KEY
    """
    admin_key_expected = os.getenv('ADMIN_API_KEY')
    if not admin_key_expected:
        # Development mode - admin key not required
        return True
    return admin_key == admin_key_expected


def require_admin(admin_key: Optional[str] = None):
    """Raise exception if admin key is invalid"""
    if not validate_admin_key(admin_key):
        raise HTTPException(status_code=403, detail=ERROR_ADMIN_ACCESS_REQUIRED)


# ============================================================================
# STARTUP/SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize multi-tenant detector on startup"""
    global detector, update_scheduler
    
    # Configuration from environment
    base_model_dir = Path(os.getenv(
        'MODEL_DIR', 
        '/app/artifacts/ensemble_model_export'
    ))
    storage_dir = Path(os.getenv(
        'STORAGE_DIR',
        '/app/data/multi_tenant'
    ))
    warmup_threshold = int(os.getenv('WARMUP_THRESHOLD', '10000'))
    teacher_update_days = int(os.getenv('TEACHER_UPDATE_DAYS', '7'))
    device = os.getenv('DEVICE', 'cpu')
    
    # Fallback paths for development
    if not base_model_dir.exists():
        repo_root = Path(__file__).parent.parent.parent
        base_model_dir = repo_root / 'artifacts/ensemble_model_export'
    
    if not storage_dir.exists():
        storage_dir = Path(__file__).parent.parent / 'data/multi_tenant'
    
    if not base_model_dir.exists():
        logger.error(f"Model directory not found: {base_model_dir}")
        logger.error("Please run model export first")
        return
    
    try:
        # Initialize detector
        detector = MultiTenantDetector(
            base_model_dir=base_model_dir,
            storage_dir=storage_dir,
            default_warmup_threshold=warmup_threshold,
            window_size=20,
            device=device,
            teacher_update_interval_days=teacher_update_days
        )
        
        # Initialize update scheduler
        update_scheduler = TeacherUpdateScheduler(
            multi_tenant_detector=detector,
            update_interval_hours=teacher_update_days * 24,
            min_new_samples=5000
        )
        
        # Start background scheduler
        update_scheduler.start_background_scheduler()

        # Start background session-expiry thread (fix 5)
        detector.start_background_cleanup()

        # Start background project-state flush thread (fix 7)
        detector.project_manager.start_background_flush()

        teacher_info = detector.teacher.get_model_info()
        logger.info("Teacher startup summary:")
        logger.info("  Base model dir: %s", base_model_dir)
        logger.info("  Storage dir: %s", storage_dir)
        logger.info(
            "  Base artifacts present: transformer=%s isolation_forest=%s",
            teacher_info.get('base_transformer_artifact_present'),
            teacher_info.get('base_iso_artifact_present'),
        )
        logger.info(
            "  Saved teacher state present: transformer=%s isolation_forest=%s",
            teacher_info.get('saved_transformer_present'),
            teacher_info.get('saved_iso_present'),
        )
        logger.info(
            "  Teacher readiness: loaded=%s iso_forest_status=%s vocab_size=%s",
            teacher_info.get('is_loaded'),
            teacher_info.get('iso_forest_status'),
            teacher_info.get('vocab_size'),
        )
        
        logger.info("Multi-tenant detector initialized successfully!")
        
    except Exception as e:
        logger.error(f"Failed to initialize: {e}")
        import traceback
        traceback.print_exc()


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global detector, update_scheduler
    if update_scheduler:
        update_scheduler.stop_background_scheduler()
    if detector:
        detector.stop_background_cleanup()
        # Flush any pending dirty state synchronously before the process exits (fix 7)
        detector.project_manager.stop_background_flush()


# ============================================================================
# PUBLIC ENDPOINTS (No API Key Required)
# ============================================================================

@app.get("/", response_model=Dict)
async def root():
    """Root endpoint with API documentation"""
    return {
        "message": "Multi-Tenant Log Anomaly Detection API",
        "version": "3.0.0",
        "architecture": "student-teacher",
        "endpoints": {
            "public": {
                "health": "GET /health",
                "create_project": "POST /projects",
                "list_projects": "GET /projects (admin)",
            },
            "authenticated": {
                "detect": "POST /detect (X-API-Key)",
                "detect_batch": "POST /detect/batch (X-API-Key)",
                "project_status": "GET /project/status (X-API-Key)",
            },
            "internal": {
                "register_project": "POST /internal/projects/register",
                "project_ingest_stats": "POST /internal/projects/ingest-stats",
                "detect_structured": "POST /detect/structured",
                "detect_structured_batch": "POST /detect/batch/structured",
                "metrics": "GET /metrics",
            },
            "admin": {
                "teacher_info": "GET /admin/teacher",
                "force_teacher_update": "POST /admin/teacher/update",
            }
        }
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint (public)"""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
    
    health = detector.get_health()
    
    return HealthResponse(
        status=health['status'],
        teacher_loaded=health['teacher_loaded'],
        total_projects=health['total_projects'],
        active_student_models=health['active_student_models'],
        training_in_progress=health['training_in_progress']
    )


@app.get("/metrics", response_model=Dict[str, Any])
async def metrics():
    """Lightweight runtime metrics for the detector service."""
    return runtime_metrics.snapshot()


@app.get("/metrics/detailed", response_model=Dict[str, Any])
async def metrics_detailed(
    admin_key: Annotated[Optional[str], Query(description=ADMIN_API_KEY_DESCRIPTION)] = None,
):
    """Detailed metrics including per-project online learning and escalation stats."""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)

    require_admin(admin_key)

    base = runtime_metrics.snapshot()
    student_stats = {}
    for pid, student in detector.students.items():
        info = student.get_model_info()
        student_stats[pid] = {
            "logs_processed": info.get("logs_processed", 0),
            "online_update_count": info.get("online_update_count", 0),
            "logs_since_last_update": info.get("logs_since_last_update", 0),
            "last_online_update_at": info.get("last_online_update_at"),
            "clean_reservoir_size": info.get("clean_normal_reservoir_count", 0),
            "transformer_threshold": info.get("transformer_threshold"),
            "is_trained": info.get("is_trained", False),
        }

    base["student_models"] = student_stats
    base["escalation"] = {
        "enabled": detector.teacher_escalation_enabled,
        "entropy_threshold": detector.escalation_entropy_threshold,
        "unknown_ratio_threshold": detector.escalation_unknown_ratio_threshold,
        "max_rate": detector.escalation_max_rate,
        "recent_window_size": len(detector._escalation_window),
        "recent_escalation_count": sum(detector._escalation_window) if detector._escalation_window else 0,
    }
    base["online_updates"] = {
        "enabled": detector.online_update_enabled,
        "interval": detector.online_update_interval,
    }
    return base


# ============================================================================
# PROJECT MANAGEMENT ENDPOINTS
# ============================================================================

@app.post("/projects", response_model=CreateProjectResponse)
async def create_project(request: CreateProjectRequest):
    """
    Create a new project with unique API key.
    
    **Note**: The API key is shown only once! Store it securely.
    """
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
    
    try:
        project_id, api_key = detector.create_project(
            project_name=request.project_name,
            warmup_threshold=request.warmup_threshold,
            metadata=request.metadata
        )
        
        project = detector.project_manager.get_project(project_id)
        if project is None:
            raise HTTPException(status_code=500, detail="Failed to retrieve created project")
        
        return CreateProjectResponse(
            project_id=project_id,
            project_name=request.project_name,
            api_key=api_key,
            warmup_threshold=project.warmup_threshold,
            es_index_pattern=project.es_index_pattern or f"logs-{project_id}"
        )
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/projects", response_model=List[ProjectStatusResponse])
async def list_projects(
    admin_key: Annotated[Optional[str], Query(description=ADMIN_API_KEY_DESCRIPTION)] = None,
):
    """
    List all projects (admin only in production).
    
    In development, this is open. In production, require admin key.
    """
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
    
    require_admin(admin_key)
    
    projects = detector.list_projects()
    
    return [
        ProjectStatusResponse(
            project_id=p['project_id'],
            project_name=p['project_name'],
            phase=p['phase'],
            log_count=p['log_count'],
            warmup_threshold=p['warmup_threshold'],
            warmup_progress=p['warmup_progress'],
            has_student_model=p['has_student_model'],
            traffic_profile=p.get('traffic_profile', 'standard'),
            low_sample_calibration=p.get('low_sample_calibration', False),
            created_at=p['created_at'],
            last_activity=p['last_activity']
        )
        for p in projects
    ]


@app.delete("/projects/{project_id}")
async def delete_project(
    project_id: str,
    admin_key: Annotated[Optional[str], Query(description=ADMIN_API_KEY_DESCRIPTION)] = None,
):
    """Delete a project (admin only)"""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
    
    require_admin(admin_key)
    
    success = detector.delete_project(project_id)
    if not success:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {"message": f"Project {project_id} deleted"}


@app.post("/internal/projects/register")
async def register_project_internal(request: InternalProjectRequest):
    """Register or update a backend-owned project in detector storage."""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)

    return detector.ensure_project(
        project_id=request.project_id,
        project_name=request.project_name,
        warmup_threshold=request.warmup_threshold,
        metadata={**(request.metadata or {}), "traffic_profile": request.traffic_profile or "standard"},
    )


@app.post("/internal/projects/ingest-stats")
async def record_project_ingest_stats_internal(request: ProjectIngestStatsRequest):
    """Record ingest quality metrics for project qualification gates."""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)

    status = detector.record_project_ingest_stats(
        request.project_id,
        total_records=request.total_records,
        parse_failures=request.parse_failures,
        baseline_eligible=request.baseline_eligible,
        clean_baseline_count=request.clean_baseline_count,
        dirty_excluded_count=request.dirty_excluded_count,
        probe_skipped_count=request.probe_skipped_count,
        distinct_template_count=request.distinct_template_count,
        observed_hours=request.observed_hours,
        data_quality_incident_open=request.data_quality_incident_open,
        traffic_profile=request.traffic_profile,
    )
    if status is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return status


@app.get("/internal/projects/{project_id}/status")
async def get_project_status_internal(project_id: str):
    """Return detailed project detector state for backend dashboards."""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)

    status = detector.get_project_status(project_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return status


# ============================================================================
# AUTHENTICATED ENDPOINTS (API Key Required)
# ============================================================================

@app.get("/project/status", response_model=ProjectStatusResponse)
async def get_project_status(
    project_id: Annotated[str, Depends(get_project_from_api_key)],
):
    """Get status of authenticated project"""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
        
    status = detector.get_project_status(project_id)
    if not status:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return ProjectStatusResponse(
        project_id=status['project_id'],
        project_name=status['project_name'],
        phase=status['phase'],
        log_count=status['log_count'],
        warmup_threshold=status['warmup_threshold'],
        warmup_progress=status['warmup_progress'],
        has_student_model=status['has_student_model'],
        traffic_profile=status.get('traffic_profile', 'standard'),
        low_sample_calibration=status.get('low_sample_calibration', False),
        created_at=status['created_at'],
        last_activity=status['last_activity']
    )


@app.post("/detect", response_model=DetectionResponse)
async def detect_single(
    request: LogRequest,
    api_key: Annotated[str, Header(alias="X-API-Key")],
):
    """
    Detect anomaly in a single log line.
    
    During warmup phase, uses teacher model.
    After training, uses project-specific student model.
    
    Example:
    ```
    POST /detect
    X-API-Key: sk-your-api-key
    {
        "log_line": "192.168.1.1 - - [22/Oct/2025:10:30:45 +0000] \"GET /admin' OR '1'='1 HTTP/1.1\" 403 1234",
        "session_id": "192.168.1.1"
    }
    ```
    """
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
    
    try:
        result = detector.detect(
            api_key=api_key,
            log_line=request.log_line,
            session_id=request.session_id
        )
        
        if 'error' in result and result.get('error') == 'Invalid API key':
            raise HTTPException(status_code=401, detail=ERROR_INVALID_API_KEY)
        
        if 'error' in result:
            raise HTTPException(status_code=400, detail=result['error'])
        
        return DetectionResponse(
            is_anomaly=result['is_anomaly'],
            anomaly_score=result['anomaly_score'],
            model_type=result.get('using_model', 'unknown'),
            phase=result['phase'],
            project_id=result['project_id'],
            project_name=result['project_name'],
            log_count=result['log_count'],
            warmup_progress=result['warmup_progress'],
            timestamp=datetime.now().isoformat(),
            details={
                'rule_based': result.get('rule_based', {}),
                'isolation_forest': result.get('isolation_forest', {}),
                'transformer': result.get('transformer', {}),
                'ensemble': result.get('ensemble', {}),
                'log_data': result.get('log_data', {})
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Detection failed: {str(e)}")


@app.post("/detect/batch", response_model=BatchDetectionResponse)
async def detect_batch(
    request: BatchLogRequest,
    api_key: Annotated[str, Header(alias="X-API-Key")],
):
    """
    Detect anomalies in multiple log lines.
    
    Example:
    ```
    POST /detect/batch
    X-API-Key: sk-your-api-key
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
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
    
    # Validate API key first
    project_id = detector.validate_api_key(api_key)
    if not project_id:
        raise HTTPException(status_code=401, detail=ERROR_INVALID_API_KEY)
    
    results = []
    anomaly_count = 0
    
    for log_line in request.log_lines:
        try:
            result = detector.detect(
                api_key=api_key,
                log_line=log_line,
                session_id=request.session_id
            )
            
            if 'error' not in result:
                results.append(DetectionResponse(
                    is_anomaly=result['is_anomaly'],
                    anomaly_score=result['anomaly_score'],
                    model_type=result.get('using_model', 'unknown'),
                    phase=result['phase'],
                    project_id=result['project_id'],
                    project_name=result['project_name'],
                    log_count=result['log_count'],
                    warmup_progress=result['warmup_progress'],
                    timestamp=datetime.now().isoformat(),
                    details={
                        'rule_based': result.get('rule_based', {}),
                        'isolation_forest': result.get('isolation_forest', {}),
                        'transformer': result.get('transformer', {}),
                        'ensemble': result.get('ensemble', {}),
                        'log_data': result.get('log_data', {})
                    }
                ))
                
                if result['is_anomaly']:
                    anomaly_count += 1
                    
        except Exception as e:
            logger.error(f"Error processing log: {e}")
            continue
    
    return BatchDetectionResponse(
        results=results,
        total_logs=len(results),
        anomalies_detected=anomaly_count,
        project_id=project_id
    )


@app.post("/detect/structured", response_model=DetectionResponse)
async def detect_structured(request: StructuredLogRequest):
    """Internal structured detection endpoint used by the backend ingest pipeline."""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)

    result = detector.detect_structured(
        project_id=request.project_id,
        project_name=request.project_name,
        warmup_threshold=request.warmup_threshold,
        session_key=request.session_key,
        event_time=request.event_time,
        normalized_event=request.normalized_event,
        raw_log=request.raw_log,
        parsed_fields=request.parsed_fields,
        traffic_class=request.traffic_class,
        flags=request.flags,
        metadata=request.metadata,
    )
    if 'error' in result:
        raise HTTPException(status_code=400, detail=result['error'])

    return DetectionResponse(
        is_anomaly=result['is_anomaly'],
        anomaly_score=result['anomaly_score'],
        model_type=result.get('using_model', 'teacher'),
        phase=result['phase'],
        project_id=result['project_id'],
        project_name=result['project_name'],
        log_count=result['log_count'],
        warmup_progress=result['warmup_progress'],
        timestamp=datetime.now().isoformat(),
        details=result,
    )


@app.post("/detect/batch/structured", response_model=BatchDetectionResponse)
async def detect_batch_structured(request: StructuredBatchLogRequest):
    """Internal structured batch detection endpoint used by backend ingest."""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)

    results: List[DetectionResponse] = []
    anomaly_count = 0
    project_id = request.events[0].project_id if request.events else ""

    for event in request.events:
        result = detector.detect_structured(
            project_id=event.project_id,
            project_name=event.project_name,
            warmup_threshold=event.warmup_threshold,
            session_key=event.session_key,
            event_time=event.event_time,
            normalized_event=event.normalized_event,
            raw_log=event.raw_log,
            parsed_fields=event.parsed_fields,
            traffic_class=event.traffic_class,
            flags=event.flags,
            metadata=event.metadata,
        )
        if 'error' in result:
            logger.warning("Structured detection failed for project %s: %s", event.project_id, result['error'])
            continue
        results.append(
            DetectionResponse(
                is_anomaly=result['is_anomaly'],
                anomaly_score=result['anomaly_score'],
                model_type=result.get('using_model', 'teacher'),
                phase=result['phase'],
                project_id=result['project_id'],
                project_name=result['project_name'],
                log_count=result['log_count'],
                warmup_progress=result['warmup_progress'],
                timestamp=datetime.now().isoformat(),
                details=result,
            )
        )
        if result['is_anomaly']:
            anomaly_count += 1

    return BatchDetectionResponse(
        results=results,
        total_logs=len(results),
        anomalies_detected=anomaly_count,
        project_id=project_id,
    )


@app.post("/project/reset-sessions")
async def reset_project_sessions(
    project_id: Annotated[str, Depends(get_project_from_api_key)],
):
    """Reset all session history for a project"""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
        
    detector.reset_all_project_sessions(project_id)
    return {"message": "All sessions reset"}


@app.post("/project/reset-session/{session_id}")
async def reset_session(
    session_id: str,
    project_id: Annotated[str, Depends(get_project_from_api_key)],
):
    """Reset a specific session for a project"""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
        
    detector.reset_project_session(project_id, session_id)
    return {"message": f"Session {session_id} reset"}


# ============================================================================
# ADMIN ENDPOINTS
# ============================================================================

@app.get("/admin/teacher", response_model=TeacherInfoResponse)
async def get_teacher_info(
    admin_key: Annotated[Optional[str], Query(description=ADMIN_API_KEY_DESCRIPTION)] = None,
):
    """Get teacher model information (admin)"""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
    
    require_admin(admin_key)
    
    info = detector.teacher.get_model_info()
    
    return TeacherInfoResponse(
        vocab_size=info['vocab_size'],
        num_templates=info['num_templates'],
        transformer_threshold=info['transformer_threshold'],
        total_logs_processed=info['total_logs_processed'],
        is_training=info['is_training']
    )


@app.post("/admin/teacher/update")
async def force_teacher_update(
    background_tasks: BackgroundTasks,
    admin_key: Annotated[Optional[str], Query(description=ADMIN_API_KEY_DESCRIPTION)] = None,
):
    """Force immediate teacher model update (admin)"""
    if detector is None:
        raise HTTPException(status_code=503, detail=ERROR_DETECTOR_NOT_INITIALIZED)
    
    require_admin(admin_key)
    
    background_tasks.add_task(detector.update_teacher_from_students, True)
    
    return {"message": "Teacher update scheduled"}


@app.get("/admin/update-history")
async def get_update_history(
    admin_key: Annotated[Optional[str], Query(description=ADMIN_API_KEY_DESCRIPTION)] = None,
):
    """Get teacher update history (admin)"""
    if update_scheduler is None:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    
    return {
        "last_update": update_scheduler.last_update.isoformat() if update_scheduler.last_update else None,
        "history": update_scheduler.update_history
    }


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run the API server"""
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', os.getenv('ANOMALY_SERVICE_PORT', '8001')))
    reload = os.getenv('RELOAD', 'false').lower() == 'true'
    
    uvicorn.run(
        "server_multi_tenant:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )


if __name__ == "__main__":
    main()
