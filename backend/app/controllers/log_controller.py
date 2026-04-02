"""
Log Controller
Handles log-related API endpoints
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Query
from fastapi.responses import StreamingResponse
from typing import Annotated, Any, Optional
import uuid
import json
import logging
from datetime import datetime, timezone
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
from app.utils.runtime_metrics import runtime_metrics


router = APIRouter()
logger = logging.getLogger(__name__)

PROJECT_ID_FILTER_DESCRIPTION = "Project ID to filter logs"
PROJECT_ACCESS_DENIED = "You don't have access to this project"
PROJECT_NOT_FOUND = "Project not found"

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


async def _resolve_log_scope(
    current_user: dict[str, Any],
    project_id: str | None,
    db: AsyncSession,
    *,
    missing_org_detail: str,
) -> tuple[str | None, str | None]:
    from app.services.project_service import ProjectService

    project_service = ProjectService()
    if project_id:
        if current_user.get("role") != "admin":
            user_role = await project_service.check_user_project_access(
                current_user.get("uid"),
                project_id,
                db,
            )
            if not user_role:
                raise HTTPException(status_code=403, detail=PROJECT_ACCESS_DENIED)

        project = await project_service.get_project_by_id(project_id, db)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        return project.org_id, project_id

    if current_user.get("role") == "admin":
        return None, None

    org_id = current_user.get("org_id")
    if not org_id:
        raise HTTPException(status_code=403, detail=missing_org_detail)
    return org_id, None


def _build_search_window(from_date: str | None, to_date: str | None) -> tuple[str | None, str | None]:
    from_dt = f"{from_date}T00:00:00Z" if from_date else None
    to_dt = f"{to_date}T23:59:59Z" if to_date else None
    return from_dt, to_dt


def _resolve_infected_filter(malicious: bool | None) -> bool | None:
    if malicious is None:
        return None
    return malicious


async def _get_project_record(project_id: str, db: AsyncSession):
    from sqlalchemy import select
    from app.models.project_db import ProjectDB

    result = await db.execute(select(ProjectDB).where(ProjectDB.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
    return project


def _get_log_parser(log_parser_service: LogParserService, log_type: str):
    return log_parser_service.parse_nginx_log if log_type == "nginx" else log_parser_service.parse_apache_log


def _parse_logs_for_storage(
    raw_logs: list[str],
    log_parser_service: LogParserService,
    log_type: str,
) -> list[dict[str, Any]]:
    parser = _get_log_parser(log_parser_service, log_type)
    parsed_logs_data: list[dict[str, Any]] = []

    for index, raw_log in enumerate(raw_logs):
        try:
            parsed_log = parser(raw_log)
            if parsed_log is None:
                logger.warning("Could not parse %s log entry", log_type)
                continue
            parsed_logs_data.append(
                LogSerializer.serialize_parsed_log_data(parsed_log, raw_log, index)
            )
        except Exception as exc:
            logger.error("Error parsing %s log: %s", log_type, exc)

    return parsed_logs_data


def _collect_unique_ips(parsed_logs_data: list[dict[str, Any]]) -> set[str]:
    return {
        parsed_log["parsed_log"].get("ip_address")
        for parsed_log in parsed_logs_data
        if parsed_log["parsed_log"].get("ip_address")
    }


def _build_default_anomaly_results(raw_logs: list[str]) -> list[dict[str, Any]]:
    return [{"is_anomaly": False, "anomaly_score": 0.0, "details": {}}] * len(raw_logs)


def _parse_report_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _validate_report_window(start_dt: datetime, end_dt: datetime) -> None:
    if end_dt <= start_dt:
        raise HTTPException(
            status_code=400,
            detail="End time must be after start time"
        )

    duration = end_dt - start_dt
    if duration.days > 30:
        raise HTTPException(
            status_code=400,
            detail="Time range cannot exceed 30 days"
        )


async def _resolve_report_scope(
    request: GenerateReportRequest,
    current_user: dict[str, Any],
    db: AsyncSession,
) -> tuple[str | None, str | None, str, str | None]:
    from app.services.project_service import ProjectService

    project_service = ProjectService()

    if request.project_id:
        project = await project_service.get_project_by_id(request.project_id, db)
        if not project:
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)

        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager"
            and current_user.get("org_id") == project.org_id
        )
        member_role = await project_service.check_user_project_access(
            current_user.get("uid"),
            request.project_id,
            db,
        )
        if not (is_admin or is_manager_in_org or member_role):
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to generate a report for this project"
            )

        return project.org_id, request.project_id, "project", project.name

    org_id = current_user.get("org_id")
    if not org_id and current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Please select a project or ensure your account belongs to an organization"
        )
    return org_id, None, "organization", None

@router.get(
    "/fetch",
    response_model=LogEntryResponse,
    responses={
        403: {"description": "User does not have access to the requested logs."},
        404: {"description": "Project not found."},
        500: {"description": "Failed to fetch logs."},
    },
)
async def fetch_logs(
    limit: int = 100,
    offset: int = 0,
    project_id: Annotated[str | None, Query(description=PROJECT_ID_FILTER_DESCRIPTION)] = None,
    elasticsearch_service: Annotated[ElasticsearchService, Depends(get_elasticsearch_service)] = None,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
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
        org_id_filter, project_id_filter = await _resolve_log_scope(
            current_user,
            project_id,
            db,
            missing_org_detail="Please select a project to view logs",
        )
        
        # Cap limit to 100 max
        safe_limit = min(max(limit, 1), 100)
        safe_offset = max(offset, 0)
        logger.info("Fetching logs with limit=%s offset=%s", safe_limit, safe_offset)
        
        # Fetch logs from Elasticsearch with pagination
        result = await elasticsearch_service.get_logs(
            org_id=org_id_filter,
            project_id=project_id_filter,
            limit=safe_limit,
            offset=safe_offset,
        )
        logger.info("Fetched %s logs", len(result.get("logs", [])))
        
        return LogSerializer.build_log_response(
            result["logs"],
            result.get("total", 0),
            result.get("infected_count"),
            parse_failure_count=result.get("parse_failure_count", 0),
            detection_failure_count=result.get("detection_failure_count", 0),
            incident_count=result.get("incident_count", 0),
            skipped_count=result.get("skipped_count", 0),
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch logs: {str(e)}")


@router.get(
    "/search",
    response_model=LogEntryResponse,
    responses={
        403: {"description": "User does not have access to the requested logs."},
        404: {"description": "Project not found."},
        500: {"description": "Failed to search logs."},
    },
)
async def search_logs(
    ip: str | None = None,
    api: str | None = None,
    status_code: int | None = None,
    malicious: bool | None = None,
    parse_status: str | None = None,
    detection_status: str | None = None,
    incident_id: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    limit: int = 100,
    offset: int = 0,
    project_id: Annotated[str | None, Query(description=PROJECT_ID_FILTER_DESCRIPTION)] = None,
    elasticsearch_service: Annotated[ElasticsearchService, Depends(get_elasticsearch_service)] = None,
    current_user: Annotated[dict[str, Any], Depends(check_permission("/api/v1/search", "GET"))] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """
    Search logs by ip, api url, status code, or malicious/clean flag.

    Only accessible to admin and manager roles (enforced via RBAC).
    """
    try:
        org_id_filter, project_id_filter = await _resolve_log_scope(
            current_user,
            project_id,
            db,
            missing_org_detail="Please select a project to search logs",
        )
        
        infected = _resolve_infected_filter(malicious)
        from_dt, to_dt = _build_search_window(from_date, to_date)

        safe_limit = min(max(limit, 1), 100)
        safe_offset = max(offset, 0)
        result = await elasticsearch_service.search_logs(
            org_id=org_id_filter,
            project_id=project_id_filter,
            ip=ip,
            api=api,
            status_code=status_code,
            infected=infected,
            parse_status=parse_status,
            detection_status=detection_status,
            incident_id=incident_id,
            from_datetime=from_dt,
            to_datetime=to_dt,
            limit=safe_limit,
            offset=safe_offset,
        )

        return LogSerializer.build_log_response(
            result["logs"],
            result.get("total", 0),
            result.get("infected_count"),
            parse_failure_count=result.get("parse_failure_count", 0),
            detection_failure_count=result.get("detection_failure_count", 0),
            incident_count=result.get("incident_count", 0),
            skipped_count=result.get("skipped_count", 0),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error searching logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to search logs: {str(e)}")

@router.get(
    "/export",
    responses={
        403: {"description": "User does not have access to the requested logs."},
        404: {"description": "Project not found."},
        500: {"description": "Failed to export logs."},
    },
)
async def export_logs_to_csv(
    ip: str | None = None,
    api: str | None = None,
    status_code: int | None = None,
    malicious: bool | None = None,
    parse_status: str | None = None,
    detection_status: str | None = None,
    incident_id: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    project_id: Annotated[str | None, Query(description=PROJECT_ID_FILTER_DESCRIPTION)] = None,
    elasticsearch_service: Annotated[ElasticsearchService, Depends(get_elasticsearch_service)] = None,
    log_service: Annotated[LogService, Depends(get_log_service)] = None,
    current_user: Annotated[dict[str, Any], Depends(check_permission("/api/v1/export", "GET"))] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """
    Export logs to CSV with anomaly scores for each model.
    
    Only accessible to admin and manager roles (enforced via RBAC).
    Supports the same filters as search endpoint.
    """
    try:
        org_id_filter, project_id_filter = await _resolve_log_scope(
            current_user,
            project_id,
            db,
            missing_org_detail="Please select a project to export logs",
        )
        
        infected = _resolve_infected_filter(malicious)
        from_dt, to_dt = _build_search_window(from_date, to_date)

        # Get all matching logs (up to 10000 for export)
        result = await elasticsearch_service.search_logs(
            org_id=org_id_filter,
            project_id=project_id_filter,
            ip=ip,
            api=api,
            status_code=status_code,
            infected=infected,
            parse_status=parse_status,
            detection_status=detection_status,
            incident_id=incident_id,
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


@router.post(
    "/correctLog",
    responses={
        400: {"description": "The correction request is invalid."},
        403: {"description": "User must belong to an organization to correct logs."},
    },
)
async def correct_log(
    request: CorrectLogRequest,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
    elasticsearch_service: Annotated[ElasticsearchService, Depends(get_elasticsearch_service)] = None,
    log_service: Annotated[LogService, Depends(get_log_service)] = None,
    current_user: Annotated[dict[str, Any], Depends(check_permission("/api/v1/correctLog", "POST"))] = None,
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

@router.post(
    "/agent/debug-logs",
    responses={
        500: {"description": "Debug logging failed."},
    },
)
async def debug_fluent_bit_logs(
    request: Request,
    project_id: Annotated[str, Depends(validate_api_key)] = None,
):
    """
    Debug endpoint to log exactly what Fluent-bit is sending
    """
    try:
        body = await request.body()
        headers = dict(request.headers)
        
        logger.info("Fluent Bit debug request received for an authenticated project")
        logger.info("Debug payload type=%s length=%s header_count=%s", type(body).__name__, len(body), len(headers))
        
        # Try to parse as JSON
        try:
            parsed_data = json.loads(body)
            record_count = len(parsed_data) if isinstance(parsed_data, list) else 1
            logger.info("Debug payload parsed as JSON type=%s records=%s", type(parsed_data).__name__, record_count)
        except Exception as parse_error:
            logger.info("Debug payload was not valid JSON: %s", parse_error)
            
        return {"status": "debug_complete", "body_length": len(body), "project_authenticated": bool(project_id)}
        
    except Exception as e:
        logger.error(f"Debug endpoint error: {e}")
        return {"status": "debug_error", "error": str(e)}

@router.post(
    "/agent/send-logs",
    responses={
        400: {"description": "No valid logs found in request."},
        404: {"description": "Project not found."},
        500: {"description": "Failed to process logs."},
    },
)
async def receive_fluent_bit_logs(
    request: Request,
    elasticsearch_service: Annotated[ElasticsearchService, Depends(get_elasticsearch_service)] = None,
    log_parser_service: Annotated[LogParserService, Depends(get_log_parser_service)] = None,
    anomaly_detection_service: Annotated[AnomalyDetectionService, Depends(get_anomaly_detection_service)] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
    project_id: Annotated[str, Depends(validate_api_key)] = None,
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
        runtime_metrics.increment("ingest_batches_total")

        # Fetch project to get log_type
        project = await _get_project_record(project_id, db)
        log_type = project.log_type  # Get the log type (apache or nginx)
        logger.info("Processing Fluent Bit logs with parser=%s", log_type)
        await anomaly_detection_service.register_or_update_project(
            project_id=project.id,
            project_name=project.name,
            warmup_threshold=project.warmup_threshold or 10000,
            metadata={
                "log_type": log_type,
                "org_id": project.org_id,
                "traffic_profile": getattr(project, "traffic_profile", "standard") or "standard",
            },
        )

        # Parse the raw request body
        body = await request.body()
        
        logger.info("Received Fluent Bit payload length=%s bytes", len(body))
        
        request_data = LogService.parse_fluent_bit_request(body)
        runtime_metrics.increment("ingest_records_total", len(request_data))
        logger.info(
            "Parsed Fluent Bit payload type=%s count=%s",
            type(request_data).__name__,
            len(request_data) if hasattr(request_data, "__len__") else "N/A",
        )
        
        candidates = LogService.extract_log_candidates(request_data)
        if not candidates:
            raise HTTPException(status_code=400, detail="No valid logs found in request")

        structured_events: list[dict[str, Any]] = []
        processed_logs: list[dict[str, Any]] = []
        seen_record_hashes: set[str] = set()
        clean_baseline_count = 0
        dirty_excluded_count = 0
        probe_skipped_count = 0
        distinct_clean_templates: set[str] = set()
        observed_hours: list[int] = []
        clean_baseline_seen_in_batch = 0

        for candidate in candidates:
            raw_log = candidate.get("raw_log")
            event_time = log_parser_service.normalize_record_timestamp(candidate.get("event_time"))
            extraction_error = candidate.get("extraction_error")
            record_hash = LogService._stable_record_hash(candidate.get("record"))

            if not raw_log:
                runtime_metrics.increment("parse_failures_total")
                processed_logs.append(
                    LogService.format_parse_failure_for_storage(
                        raw_log=None,
                        batch_id=batch_id,
                        org_id=project.org_id,
                        project_id=project.id,
                        event_time=event_time,
                        parse_error=extraction_error or "missing_raw_log",
                        source_record=candidate.get("record"),
                    )
                )
                continue

            parsed_log, parse_error = log_parser_service.parse_log_with_error(
                raw_log,
                log_type,
                fallback_event_time=event_time,
            )

            if parsed_log is None:
                runtime_metrics.increment("parse_failures_total")
                processed_logs.append(
                    LogService.format_parse_failure_for_storage(
                        raw_log=raw_log,
                        batch_id=batch_id,
                        org_id=project.org_id,
                        project_id=project.id,
                        event_time=event_time,
                        parse_error=parse_error or extraction_error or "parse_failed",
                        source_record=candidate.get("record"),
                    )
                )
                continue

            detection_context = LogService.classify_traffic(
                parsed_log=parsed_log,
                source_record=candidate.get("record"),
                raw_log=raw_log,
                event_time=parsed_log.get("timestamp", event_time),
            )
            if record_hash in seen_record_hashes:
                detection_context["flags"]["duplicate_in_batch"] = True
                detection_context["traffic_class"] = "data_quality_late_event"
                detection_context["baseline_eligible"] = False
                detection_context["decision_reason"] = "duplicate_in_batch"
                detection_context["detection_status"] = "skipped"
            seen_record_hashes.add(record_hash)

            if detection_context["traffic_class"] in {"internal_probe", "data_quality_late_event"}:
                session_key = LogService.build_session_key(project_id, parsed_log, candidate.get("record"))
                detection_error = (
                    "internal_probe_skipped"
                    if detection_context["traffic_class"] == "internal_probe"
                    else detection_context["decision_reason"]
                )
                if detection_context["traffic_class"] == "internal_probe":
                    probe_skipped_count += 1
                else:
                    dirty_excluded_count += 1
                processed_logs.append(
                    LogService.format_log_for_storage(
                        parsed_log,
                        raw_log,
                        {
                            "is_anomaly": False,
                            "anomaly_score": 0.0,
                            "raw_anomaly_score": 0.0,
                            "policy_score": 0.0,
                            "final_decision": "skipped",
                            "decision_reason": detection_context["decision_reason"],
                            "component_status": {
                                "rule_based": "skipped",
                                "isolation_forest": "skipped",
                                "transformer": "skipped",
                            },
                            "details": {
                                "rule_based": {},
                                "isolation_forest": {"status": "skipped"},
                                "transformer": {"status": "skipped"},
                                "ensemble": {"score": 0.0, "active_models": 0},
                            },
                            "detection_status": "skipped",
                            "detection_error": detection_error,
                            "model_version": "student-teacher-v1",
                            "feature_schema_version": "access-log-v2",
                            "phase": "skipped",
                            "model_type": None,
                        },
                        {},
                        batch_id,
                        project.org_id,
                        project.id,
                        session_key_hash=LogService.build_session_key_hash(session_key),
                        parse_status="parsed",
                        parse_error=None,
                        detection_status="skipped",
                        detection_error=detection_error,
                        traffic_class=detection_context["traffic_class"],
                        baseline_eligible=False,
                        decision_reason=detection_context["decision_reason"],
                    )
                )
                continue

            session_key = LogService.build_session_key(project_id, parsed_log, candidate.get("record"))
            if detection_context["baseline_eligible"]:
                clean_baseline_seen_in_batch += 1
                clean_baseline_count += 1
                distinct_clean_templates.add(parsed_log.get("normalized_event") or "")
                try:
                    observed_hours.append(
                        datetime.fromisoformat(
                            (parsed_log.get("timestamp", event_time) or "").replace("Z", "+00:00")
                        ).hour
                    )
                except Exception:
                    pass
            else:
                dirty_excluded_count += 1

            structured_events.append(
                {
                    "parsed_log": parsed_log,
                    "raw_log": raw_log,
                    "session_key": session_key,
                    "session_key_hash": LogService.build_session_key_hash(session_key),
                    "project_id": project_id,
                    "log_type": log_type,
                    "event_time": parsed_log.get("timestamp", event_time),
                    "traffic_class": detection_context["traffic_class"],
                    "flags": detection_context["flags"],
                    "baseline_eligible": detection_context["baseline_eligible"],
                    "decision_reason": detection_context["decision_reason"],
                    "clean_baseline_offset": clean_baseline_seen_in_batch if detection_context["baseline_eligible"] else 0,
                }
            )

        logger.info(
            "Prepared %s structured events and %s parse failures from Fluent Bit payload",
            len(structured_events),
            len(processed_logs),
        )

        parse_failures = sum(1 for log in processed_logs if log.get("parse_status") == "failed")

        if not structured_events and not processed_logs:
            raise HTTPException(status_code=400, detail="No valid logs found in request")

        detection_results = await anomaly_detection_service.detect_batch_structured_logs(
            events=[
                {
                    "project_id": event["project_id"],
                    "project_name": project.name,
                    "warmup_threshold": project.warmup_threshold or 10000,
                    "session_key": event["session_key"],
                    "log_type": log_type,
                    "event_time": event["event_time"],
                    "normalized_event": event["parsed_log"].get("normalized_event"),
                    "raw_log": event["raw_log"],
                    "traffic_class": event["traffic_class"],
                    "parsed_fields": {
                        "ip_address": event["parsed_log"].get("ip_address"),
                        "method": event["parsed_log"].get("method"),
                        "path": event["parsed_log"].get("path"),
                        "protocol": event["parsed_log"].get("protocol"),
                        "status_code": event["parsed_log"].get("status_code"),
                        "size": event["parsed_log"].get("size"),
                        "auth_user": event["parsed_log"].get("auth_user"),
                        "referer": event["parsed_log"].get("referer"),
                        "user_agent": event["parsed_log"].get("user_agent"),
                        "session_key_hash": event["session_key_hash"],
                    },
                    "flags": event["flags"],
                    "metadata": {
                        "log_type": log_type,
                        "org_id": project.org_id,
                        "traffic_profile": getattr(project, "traffic_profile", "standard") or "standard",
                        "clean_baseline_offset": event["clean_baseline_offset"],
                    },
                }
                for event in structured_events
            ]
        )

        if detection_results is None:
            runtime_metrics.increment("detector_failures_total", len(structured_events))
            detection_results = [
                {
                    "is_anomaly": False,
                    "anomaly_score": 0.0,
                    "details": {},
                    "detection_status": "failed",
                    "detection_error": "detector_unavailable",
                    "final_decision": "detection_failed",
                    "decision_reason": "detector_unavailable",
                    "component_status": {},
                    "model_version": "adaptive-v2",
                    "feature_schema_version": "access-log-v1",
                }
                for _ in structured_events
            ]

        unique_ips = {
            event["parsed_log"].get("ip_address")
            for event in structured_events
            if event["parsed_log"].get("ip_address")
        }
        
        # Query IP table for status overrides
        ip_status_map = await LogService.get_ip_status_map(unique_ips, project.org_id, db)
        
        for index, event in enumerate(structured_events):
            anomaly_result = detection_results[index] if index < len(detection_results) else {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "details": {},
                "detection_status": "failed",
                "detection_error": "missing_detection_result",
                "final_decision": "detection_failed",
                "decision_reason": "missing_detection_result",
                "component_status": {},
                "model_version": "adaptive-v2",
                "feature_schema_version": "access-log-v1",
            }

            detection_status = anomaly_result.get("detection_status", "scored")
            if detection_status != "scored":
                runtime_metrics.increment("detector_failures_total")

            processed_logs.append(
                LogService.format_log_for_storage(
                    event["parsed_log"],
                    event["raw_log"],
                    anomaly_result,
                    ip_status_map,
                    batch_id,
                    project.org_id,
                    project.id,
                    session_key_hash=event["session_key_hash"],
                    parse_status="parsed",
                    parse_error=None,
                    detection_status=detection_status,
                    detection_error=anomaly_result.get("detection_error"),
                    traffic_class=event["traffic_class"],
                    baseline_eligible=event["baseline_eligible"],
                    decision_reason=anomaly_result.get("decision_reason", event["decision_reason"]),
                )
            )

        project_quality_status = await anomaly_detection_service.report_project_ingest_stats(
            project_id=project.id,
            total_records=len(candidates),
            parse_failures=parse_failures,
            baseline_eligible=clean_baseline_count,
            clean_baseline_count=clean_baseline_count,
            dirty_excluded_count=dirty_excluded_count,
            probe_skipped_count=probe_skipped_count,
            distinct_template_count=len([template for template in distinct_clean_templates if template]),
            observed_hours=observed_hours,
            data_quality_incident_open=(
                (parse_failures / len(candidates)) > 0.05 if candidates else False
            ),
            traffic_profile=getattr(project, "traffic_profile", "standard") or "standard",
        )
        
        # Store processed logs in Elasticsearch
        if processed_logs:
            storage_success = await elasticsearch_service.store_logs_batch(processed_logs)
            if not storage_success:
                logger.error("Failed to store logs in Elasticsearch")
                runtime_metrics.increment("storage_failures_total")
                response = LogSerializer.serialize_fluent_bit_response(
                    message="Logs processed but storage is degraded",
                    batch_id=batch_id,
                    processed_count=len(processed_logs),
                    anomalies_detected=sum(1 for log in processed_logs if log.get("infected", False)),
                    status="degraded",
                )
                return response
            
            # Send logs to WebSocket connections for real-time updates (filtered by project_id)
            await LogService.send_logs_to_websocket(processed_logs, org_id=project.org_id, project_id=project.id)
            
            # Increment project log count for warmup tracking
            model_phase = None
            if detection_results:
                model_phase = detection_results[0].get("phase")
            elif isinstance(project_quality_status, dict):
                model_phase = project_quality_status.get("phase")
            await LogService.increment_org_log_count(project_id, len(processed_logs), db, model_phase=model_phase)
        
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


@router.post(
    "/generate-report",
    responses={
        400: {"description": "The time range or payload is invalid."},
        403: {"description": "User does not have permission to generate this report."},
        404: {"description": "Project not found."},
        500: {"description": "Failed to generate the report."},
    },
)
async def generate_security_report(
    request: GenerateReportRequest,
    elasticsearch_service: Annotated[ElasticsearchService, Depends(get_elasticsearch_service)] = None,
    report_service: Annotated[ReportService, Depends(get_report_service)] = None,
    current_user: Annotated[dict[str, Any], Depends(check_permission("/api/v1/generate-report", "POST"))] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """
    Generate a PDF security report for the specified time range.

    Optionally scoped to a specific project via project_id.
    Accessible to admin and manager roles.
    """
    try:
        # Parse datetime strings
        try:
            start_dt = _parse_report_datetime(request.start_time)
            end_dt = _parse_report_datetime(request.end_time)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid datetime format. Use ISO format (YYYY-MM-DDTHH:MM:SS)"
            )

        _validate_report_window(start_dt, end_dt)
        org_id_filter, project_id_filter, report_scope, project_name = await _resolve_report_scope(
            request,
            current_user,
            db,
        )

        logger.info("Generating security report for scope=%s", report_scope)

        # Generate PDF report
        pdf_buffer = await report_service.generate_security_report(
            elasticsearch_service=elasticsearch_service,
            org_id=org_id_filter,
            project_id=project_id_filter,
            start_time=start_dt,
            end_time=end_dt,
            user_uid=current_user.get("uid")
        )

        # Build a descriptive filename
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        scope_label = project_name or project_id_filter or org_id_filter or "all"
        filename = f"security_report_{scope_label}_{timestamp}.pdf"

        logger.info("Successfully generated report: %s", filename)

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
