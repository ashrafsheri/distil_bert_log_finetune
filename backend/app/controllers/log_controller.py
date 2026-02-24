"""
Log Controller
Handles log-related API endpoints
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Query, status
from fastapi.responses import StreamingResponse
from typing import List, Optional
import uuid
import json
import logging
from datetime import datetime
from pydantic import BaseModel
from app.models.log_entry import LogEntry, LogEntryResponse, AnomalyDetails, CorrectLogRequest
from app.serializers.log_serializer import LogSerializer
from app.services.log_service import LogService
from app.services.elasticsearch_service import ElasticsearchService
from app.services.log_parser_service import LogParserService
from app.services.anomaly_detection_service import AnomalyDetectionService
from app.services.report_service import ReportService
from app.utils.firebase_auth import get_current_user, validate_api_key
from app.utils.permissions import check_permission
from sqlalchemy.ext.asyncio import AsyncSession
from app.utils.database import get_db


router = APIRouter()
logger = logging.getLogger(__name__)

# Dependency injection for services
def get_log_service() -> LogService:
    return LogService()

def get_elasticsearch_service() -> ElasticsearchService:
    return ElasticsearchService()

def get_log_parser_service() -> LogParserService:
    return LogParserService()

def get_anomaly_detection_service() -> AnomalyDetectionService:
    return AnomalyDetectionService()

def get_report_service() -> ReportService:
    return ReportService()

# Request model for report generation
class GenerateReportRequest(BaseModel):
    start_time: str  # ISO format datetime string
    end_time: str    # ISO format datetime string
    project_id: Optional[str] = None  # Optional project ID filter

@router.get("/fetch", response_model=LogEntryResponse)
async def fetch_logs(
    limit: int = 100,
    offset: int = 0,
    project_id: str = Query(None, description="Project ID to filter logs"),
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Fetch latest logs for the frontend dashboard from Elasticsearch
    
    Args:
        limit: Maximum number of logs to return (default: 100)
        offset: Number of logs to skip (default: 0)
        project_id: Optional project ID to filter logs by specific project
        
    Returns:
        LogEntryResponse: List of logs with WebSocket ID for real-time updates
    """
    try:
        print(f"[FETCH] User role: {current_user.get('role')}, org_id: {current_user.get('org_id')}, uid: {current_user.get('uid')}, project_id: {project_id}", flush=True)
        
        # Import project service for project access checks
        from app.services.project_service import ProjectService
        project_service = ProjectService()
        
        # If project_id is provided, verify user has access to the project
        org_id_filter = None
        if project_id:
            # Check if user has access to this project
            if current_user.get("role") != "admin":
                user_role = await project_service.check_user_project_access(
                    current_user.get("uid"), project_id, db
                )
                if not user_role:
                    raise HTTPException(
                        status_code=403, 
                        detail="You don't have access to this project"
                    )
            
            # Get the project to verify it exists and get org_id
            project = await project_service.get_project_by_id(project_id, db)
            if not project:
                raise HTTPException(status_code=404, detail="Project not found")
            
            # Use project's org_id for filtering (stored as project.id in ES for backward compatibility)
            org_id_filter = project_id
            print(f"[FETCH] Filtering by project: {project_id}", flush=True)
        else:
            # No project specified - show all logs user has access to
            # For admin users, don't filter by org_id (they can see all logs)
            # For other users, require org_id
            if current_user.get("role") != "admin" and not current_user.get("org_id"):
                print(f"[FETCH] User {current_user.get('uid')} has no org_id and no project_id", flush=True)
                raise HTTPException(
                    status_code=403, 
                    detail="Please select a project to view logs"
                )
            
            org_id_filter = None if current_user.get("role") == "admin" else current_user.get("org_id")
        
        # Cap limit to 100 max
        safe_limit = min(max(limit, 1), 100)
        safe_offset = max(offset, 0)
        
        print(f"[FETCH] Querying ES with org_id_filter={org_id_filter}, limit={safe_limit}, offset={safe_offset}", flush=True)
        
        # Fetch logs from Elasticsearch with pagination
        result = await elasticsearch_service.get_logs(org_id=org_id_filter, limit=safe_limit, offset=safe_offset)
        
        print(f"[FETCH] Got {len(result.get('logs', []))} logs, total={result.get('total', 0)}", flush=True)
        
        return LogSerializer.build_log_response(result["logs"], result.get("total", 0))
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"[FETCH] Error fetching logs: {e}", flush=True)
        logger.error(f"Error fetching logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch logs: {str(e)}")


@router.get("/search", response_model=LogEntryResponse)
async def search_logs(
    ip: str | None = None,
    api: str | None = None,
    status_code: int | None = None,
    malicious: bool | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    limit: int = 100,
    offset: int = 0,
    project_id: str = Query(None, description="Project ID to filter logs"),
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    current_user: dict = Depends(check_permission("/api/v1/search", "GET")),
    db: AsyncSession = Depends(get_db)
):
    """
    Search logs by ip, api url, status code, or malicious/clean flag.

    Only accessible to admin and manager roles (enforced via RBAC).
    """
    try:
        # Import project service for project access checks
        from app.services.project_service import ProjectService
        project_service = ProjectService()
        
        # Determine org_id filter based on project_id or user's org
        org_id_filter = None
        if project_id:
            # Check if user has access to this project
            if current_user.get("role") != "admin":
                user_role = await project_service.check_user_project_access(
                    current_user.get("uid"), project_id, db
                )
                if not user_role:
                    raise HTTPException(
                        status_code=403, 
                        detail="You don't have access to this project"
                    )
            
            # Use project_id for filtering
            org_id_filter = project_id
        else:
            # Check if user has org_id
            if not current_user.get("org_id"):
                raise HTTPException(status_code=403, detail="Please select a project to search logs")
            org_id_filter = current_user["org_id"]
        
        infected = None
        if malicious is not None:
            infected = True if malicious else False

        # Convert YYYY-MM-DD to ISO datetimes covering full days
        from_dt = None
        to_dt = None
        if from_date:
            from_dt = f"{from_date}T00:00:00Z"
        if to_date:
            to_dt = f"{to_date}T23:59:59Z"

        safe_limit = min(max(limit, 1), 100)
        safe_offset = max(offset, 0)
        result = await elasticsearch_service.search_logs(
            org_id=org_id_filter,
            ip=ip,
            api=api,
            status_code=status_code,
            infected=infected,
            from_datetime=from_dt,
            to_datetime=to_dt,
            limit=safe_limit,
            offset=safe_offset,
        )

        return LogSerializer.build_log_response(result["logs"], result.get("total", 0))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error searching logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to search logs: {str(e)}")

@router.get("/export")
async def export_logs_to_csv(
    ip: str | None = None,
    api: str | None = None,
    status_code: int | None = None,
    malicious: bool | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    project_id: str = Query(None, description="Project ID to filter logs"),
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    log_service: LogService = Depends(get_log_service),
    current_user: dict = Depends(check_permission("/api/v1/export", "GET")),
    db: AsyncSession = Depends(get_db)
):
    """
    Export logs to CSV with anomaly scores for each model.
    
    Only accessible to admin and manager roles (enforced via RBAC).
    Supports the same filters as search endpoint.
    """
    try:
        # Import project service for project access checks
        from app.services.project_service import ProjectService
        project_service = ProjectService()
        
        # Determine org_id filter based on project_id or user's org
        org_id_filter = None
        if project_id:
            # Check if user has access to this project
            if current_user.get("role") != "admin":
                user_role = await project_service.check_user_project_access(
                    current_user.get("uid"), project_id, db
                )
                if not user_role:
                    raise HTTPException(
                        status_code=403, 
                        detail="You don't have access to this project"
                    )
            
            # Use project_id for filtering
            org_id_filter = project_id
        else:
            # Check if user has org_id
            if not current_user.get("org_id"):
                raise HTTPException(status_code=403, detail="Please select a project to export logs")
            org_id_filter = current_user["org_id"]
        
        infected = None
        if malicious is not None:
            infected = True if malicious else False

        # Convert YYYY-MM-DD to ISO datetimes covering full days
        from_dt = None
        to_dt = None
        if from_date:
            from_dt = f"{from_date}T00:00:00Z"
        if to_date:
            to_dt = f"{to_date}T23:59:59Z"

        # Get all matching logs (up to 10000 for export)
        result = await elasticsearch_service.search_logs(
            org_id=org_id_filter,
            ip=ip,
            api=api,
            status_code=status_code,
            infected=infected,
            from_datetime=from_dt,
            to_datetime=to_dt,
            limit=10000,
            offset=0,
        )

        # Generate CSV content
        csv_content = await log_service.export_logs_to_csv(result["logs"])

        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logguard_export_{timestamp}.csv"

        # Return as downloadable file
        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.error(f"Error exporting logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to export logs: {str(e)}")


@router.post("/correctLog")
async def correct_log(
    request: CorrectLogRequest,
    db: AsyncSession = Depends(get_db),
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    log_service: LogService = Depends(get_log_service),
    current_user: dict = Depends(check_permission("/api/v1/correctLog", "POST"))
):
    """
    Correct log status for an IP address.

    Stores IP and status in PostgreSQL, then updates all logs for that IP in Elasticsearch.

    Args:
        request: Contains ip (str) and status (str: "clean" or "malicious")

    Returns:
        dict: Confirmation message with update details
    """
    try:
        # Validate user permissions
        if not current_user.get("org_id"):
            raise HTTPException(status_code=403, detail="User must belong to an organization to correct logs")

        # Delegate to service for business logic
        result = await log_service.correct_log_status(
            request=request,
            user_info=current_user,
            db=db,
            elasticsearch_service=elasticsearch_service
        )

        return result

    except ValueError as e:
        # Handle validation errors
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/agent/debug-logs")
async def debug_fluent_bit_logs(
    request: Request,
    project_id: str = Depends(validate_api_key)
):
    """
    Debug endpoint to log exactly what Fluent-bit is sending
    """
    try:
        body = await request.body()
        headers = dict(request.headers)
        
        logger.info(f"=== FLUENT-BIT DEBUG ===")
        logger.info(f"Headers: {headers}")
        logger.info(f"Body (first 1000 chars): {body[:1000]}")
        logger.info(f"Body type: {type(body)}")
        logger.info(f"Body length: {len(body)}")
        logger.info(f"Project ID from API key: {project_id}")
        
        # Try to parse as JSON
        try:
            parsed_data = json.loads(body)
            logger.info(f"Successfully parsed as JSON")
            logger.info(f"Data type: {type(parsed_data)}")
            logger.info(f"Data structure: {parsed_data[:2] if isinstance(parsed_data, list) else parsed_data}")
        except Exception as parse_error:
            logger.info(f"Failed to parse as JSON: {parse_error}")
            
        return {"status": "debug_complete", "body_length": len(body)}
        
    except Exception as e:
        logger.error(f"Debug endpoint error: {e}")
        return {"status": "debug_error", "error": str(e)}

@router.post("/agent/send-logs")
async def receive_fluent_bit_logs(
    request: Request,
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    log_parser_service: LogParserService = Depends(get_log_parser_service),
    anomaly_detection_service: AnomalyDetectionService = Depends(get_anomaly_detection_service),
    db: AsyncSession = Depends(get_db),
    project_id: str = Depends(validate_api_key)
):
    """
    Receive logs from Fluent Bit, process them through anomaly detection, and store in Elasticsearch
    
    Expected format: [{"log": "raw_log_line", "timestamp": "...", ...}, ...]
    
    Args:
        request: Raw request body from Fluent Bit
        project_id: Project ID validated from API key
        
    Returns:
        dict: Confirmation message for Fluent Bit acknowledgment
    """
    try:
        # Generate internal batch ID for tracking
        batch_id = str(uuid.uuid4())

        # Fetch project to get log_type
        from sqlalchemy import select
        from app.models.project_db import ProjectDB
        
        result = await db.execute(select(ProjectDB).where(ProjectDB.id == project_id))
        project = result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
        
        log_type = project.log_type  # Get the log type (apache or nginx)
        logger.info(f"Processing logs for project {project_id} with log_type: {log_type}")

        # Parse the raw request body
        body = await request.body()
        
        # Use print() for guaranteed visibility in Docker logs
        print(f"=== FLUENT-BIT REQUEST DEBUG ===", flush=True)
        print(f"Body length: {len(body)} bytes", flush=True)
        print(f"Body (first 500 bytes): {body[:500]}", flush=True)
        print(f"Project ID from API key: {project_id}", flush=True)
        print(f"Log type: {log_type}", flush=True)
        
        request_data = LogService.parse_fluent_bit_request(body)
        print(f"Parsed data type: {type(request_data)}, count: {len(request_data) if hasattr(request_data, '__len__') else 'N/A'}", flush=True)
        
        if request_data:
            print(f"First record sample: {request_data[0] if isinstance(request_data, list) else request_data}", flush=True)
            if isinstance(request_data, list) and len(request_data) > 0:
                first = request_data[0]
                if isinstance(first, dict):
                    print(f"First record keys: {list(first.keys())}", flush=True)

        # Extract raw logs from records
        raw_logs = LogService.extract_raw_logs_from_records(request_data)
        print(f"Extracted {len(raw_logs)} raw logs", flush=True)

        if not raw_logs:
            # Log detailed info about what we received but couldn't parse
            print(f"WARNING: No valid logs extracted. Raw request_data: {request_data[:2] if isinstance(request_data, list) else request_data}", flush=True)
            raise HTTPException(status_code=400, detail="No valid logs found in request")
        
        logger.info(f"Processing {len(raw_logs)} logs from Fluent Bit")
        
        # Process logs through anomaly detection
        anomaly_results = await anomaly_detection_service.detect_batch_logs(
            log_lines=raw_logs,
            session_id=f"fluent_bit_{batch_id}"
        )
        
        if anomaly_results is None:
            logger.warning("Anomaly detection failed, processing logs without detection")
            anomaly_results = [{"is_anomaly": False, "anomaly_score": 0.0, "details": {}}] * len(raw_logs)
        
        # Parse logs using the appropriate parser based on org's log_type
        parsed_logs_data = []
        for i, raw_log in enumerate(raw_logs):
            try:
                # Use appropriate parser based on log_type
                if log_type == "nginx":
                    parsed_log = log_parser_service.parse_nginx_log(raw_log)
                else:  # Default to apache
                    parsed_log = log_parser_service.parse_apache_log(raw_log)
                
                if parsed_log is None:
                    logger.warning(f"Could not parse {log_type} log: {raw_log[:100]}...")
                    continue
                parsed_logs_data.append(
                    LogSerializer.serialize_parsed_log_data(parsed_log, raw_log, i)
                )
            except Exception as e:
                logger.error(f"Error parsing {log_type} log: {e}")
                continue
        
        # Get unique IP addresses from parsed logs
        unique_ips = set()
        for log_data in parsed_logs_data:
            ip = log_data["parsed_log"].get("ip_address")
            if ip:
                unique_ips.add(ip)
        
        # Query IP table for status overrides
        ip_status_map = await LogService.get_ip_status_map(unique_ips, project_id, db)
        
        # Process parsed logs into formatted logs for storage
        processed_logs = await LogService.process_parsed_logs_batch(
            parsed_logs_data, anomaly_results, ip_status_map, batch_id, project_id
        )
        
        # Store processed logs in Elasticsearch
        if processed_logs:
            storage_success = await elasticsearch_service.store_logs_batch(processed_logs)
            if not storage_success:
                logger.error("Failed to store logs in Elasticsearch")
            
            # Send logs to WebSocket connections for real-time updates (filtered by project_id)
            await LogService.send_logs_to_websocket(processed_logs, org_id=project_id)
            
            # Increment project log count for warmup tracking
            await LogService.increment_org_log_count(project_id, len(processed_logs), db)
        
        processed_count = len(processed_logs)
        anomalies_detected = sum(1 for log in processed_logs if log.get("infected", False))
        logger.info(f"Successfully processed {processed_count} logs")

        # Alert managers if anomalies detected
        await LogService.send_anomaly_alert(
            anomalies_detected, processed_logs, batch_id, project_id, db
        )

        # Return serialized response
        response = LogSerializer.serialize_fluent_bit_response(
            message="Logs received and processed successfully",
            batch_id=batch_id,
            processed_count=processed_count,
            anomalies_detected=anomalies_detected
        )
        
        processed_logs.clear()
        return response
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Error processing logs: {str(e)}")
        logger.error(f"Full traceback: {error_details}")
        raise HTTPException(status_code=500, detail=f"Failed to process logs: {str(e)}")


@router.post("/generate-report")
async def generate_security_report(
    request: GenerateReportRequest,
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    report_service: ReportService = Depends(get_report_service),
    current_user: dict = Depends(check_permission("/api/v1/generate-report", "POST")),
    db: AsyncSession = Depends(get_db)
):
    """
    Generate a PDF security report for the specified time range.

    Optionally scoped to a specific project via project_id.
    Accessible to admin and manager roles.
    """
    try:
        # Parse datetime strings
        try:
            start_dt = datetime.fromisoformat(request.start_time.replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(request.end_time.replace('Z', '+00:00'))
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid datetime format. Use ISO format (YYYY-MM-DDTHH:MM:SS)"
            )

        # Validate time range
        if end_dt <= start_dt:
            raise HTTPException(
                status_code=400,
                detail="End time must be after start time"
            )

        # Check 30-day limit
        duration = end_dt - start_dt
        if duration.days > 30:
            raise HTTPException(
                status_code=400,
                detail="Time range cannot exceed 30 days"
            )

        from app.services.project_service import ProjectService
        project_service = ProjectService()

        # Determine the filter ID (project_id takes priority over org_id)
        filter_id = None
        report_scope = "organization"
        project_name = None

        if request.project_id:
            # Validate project exists
            project = await project_service.get_project_by_id(request.project_id, db)
            if not project:
                raise HTTPException(status_code=404, detail="Project not found")

            # Permission check: admin can access any project;
            # manager can access projects in their org;
            # others must be an explicit project member
            is_admin = current_user.get("role") == "admin"
            is_manager_in_org = (
                current_user.get("role") == "manager" and
                current_user.get("org_id") == project.org_id
            )
            member_role = await project_service.check_user_project_access(
                current_user.get("uid"), request.project_id, db
            )
            if not (is_admin or is_manager_in_org or member_role):
                raise HTTPException(
                    status_code=403,
                    detail="You don't have permission to generate a report for this project"
                )

            filter_id = request.project_id
            report_scope = "project"
            project_name = project.name
        else:
            # No project specified — fall back to user's org
            org_id = current_user.get("org_id")
            if not org_id and current_user.get("role") != "admin":
                raise HTTPException(
                    status_code=403,
                    detail="Please select a project or ensure your account belongs to an organization"
                )
            filter_id = org_id  # may be None for admin (all data)

        logger.info(
            f"Generating security report — scope={report_scope}, "
            f"filter_id={filter_id}, from={start_dt} to={end_dt}"
        )

        # Generate PDF report
        pdf_buffer = await report_service.generate_security_report(
            elasticsearch_service=elasticsearch_service,
            org_id=filter_id,
            start_time=start_dt,
            end_time=end_dt,
            user_uid=current_user.get("uid")
        )

        # Build a descriptive filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        scope_label = project_name or filter_id or "all"
        filename = f"security_report_{scope_label}_{timestamp}.pdf"

        logger.info(f"Successfully generated report: {filename}")

        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/pdf"
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate report: {str(e)}"
        )
