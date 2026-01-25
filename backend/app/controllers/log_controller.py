"""
Log Controller
Handles log-related API endpoints
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Query, status
from fastapi.responses import StreamingResponse
from typing import List
import uuid
import json
import logging
from datetime import datetime
from app.models.log_entry import LogEntry, LogEntryResponse, AnomalyDetails, CorrectLogRequest
from app.serializers.log_serializer import LogSerializer
from app.services.log_service import LogService
from app.services.elasticsearch_service import ElasticsearchService
from app.services.log_parser_service import LogParserService
from app.services.anomaly_detection_service import AnomalyDetectionService
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

@router.get("/fetch", response_model=LogEntryResponse)
async def fetch_logs(
    limit: int = 100,
    offset: int = 0,
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    current_user: dict = Depends(get_current_user)
):
    """
    Fetch latest logs for the frontend dashboard from Elasticsearch
    
    Args:
        limit: Maximum number of logs to return (default: 100)
        offset: Number of logs to skip (default: 0)
        
    Returns:
        LogEntryResponse: List of logs with WebSocket ID for real-time updates
    """
    try:
        # For admin users, don't filter by org_id (they can see all logs)
        # For other users, require org_id
        if current_user.get("role") != "admin" and not current_user.get("org_id"):
            raise HTTPException(status_code=403, detail="User must belong to an organization to access logs")
        
        # Cap limit to 100 max
        safe_limit = min(max(limit, 1), 100)
        safe_offset = max(offset, 0)
        
        # Determine org_id for filtering
        org_id_filter = None if current_user.get("role") == "admin" else current_user.get("org_id")
        
        # Fetch logs from Elasticsearch with pagination
        result = await elasticsearch_service.get_logs(org_id=org_id_filter, limit=safe_limit, offset=safe_offset)
        
        return LogSerializer.build_log_response(result["logs"], result.get("total", 0))
        
    except Exception as e:
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
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    current_user: dict = Depends(check_permission("/api/v1/search", "GET"))
):
    """
    Search logs by ip, api url, status code, or malicious/clean flag.

    Only accessible to admin and manager roles (enforced via RBAC).
    """
    try:
        # Check if user has org_id
        if not current_user.get("org_id"):
            raise HTTPException(status_code=403, detail="User must belong to an organization to access logs")
        
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
            org_id=current_user["org_id"],
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
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    log_service: LogService = Depends(get_log_service),
    current_user: dict = Depends(check_permission("/api/v1/export", "GET"))
):
    """
    Export logs to CSV with anomaly scores for each model.
    
    Only accessible to admin and manager roles (enforced via RBAC).
    Supports the same filters as search endpoint.
    """
    try:
        # Check if user has org_id
        if not current_user.get("org_id"):
            raise HTTPException(status_code=403, detail="User must belong to an organization to access logs")
        
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
            org_id=current_user["org_id"],
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

@router.post("/agent/send-logs")
async def receive_fluent_bit_logs(
    request: Request,
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    log_parser_service: LogParserService = Depends(get_log_parser_service),
    anomaly_detection_service: AnomalyDetectionService = Depends(get_anomaly_detection_service),
    db: AsyncSession = Depends(get_db),
    org_id: str = Depends(validate_api_key)
):
    """
    Receive logs from Fluent Bit, process them through anomaly detection, and store in Elasticsearch
    
    Expected format: [{"log": "raw_log_line", "timestamp": "...", ...}, ...]
    
    Args:
        request: Raw request body from Fluent Bit
        
    Returns:
        dict: Confirmation message for Fluent Bit acknowledgment
    """
    try:
        # Generate internal batch ID for tracking
        batch_id = str(uuid.uuid4())

        # Parse the raw request body
        body = await request.body()
        request_data = LogService.parse_fluent_bit_request(body)

        # Extract raw logs from records
        raw_logs = LogService.extract_raw_logs_from_records(request_data)

        if not raw_logs:
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
        
        # Parse logs first to get IP addresses
        parsed_logs_data = []
        for i, raw_log in enumerate(raw_logs):
            try:
                parsed_log = log_parser_service.parse_apache_log(raw_log)
                if parsed_log is None:
                    logger.warning(f"Could not parse log: {raw_log[:100]}...")
                    continue
                parsed_logs_data.append(
                    LogSerializer.serialize_parsed_log_data(parsed_log, raw_log, i)
                )
            except Exception as e:
                logger.error(f"Error parsing log: {e}")
                continue
        
        # Get unique IP addresses from parsed logs
        unique_ips = set()
        for log_data in parsed_logs_data:
            ip = log_data["parsed_log"].get("ip_address")
            if ip:
                unique_ips.add(ip)
        
        # Query IP table for status overrides
        ip_status_map = await LogService.get_ip_status_map(unique_ips, org_id, db)
        
        # Process parsed logs into formatted logs for storage
        processed_logs = await LogService.process_parsed_logs_batch(
            parsed_logs_data, anomaly_results, ip_status_map, batch_id, org_id
        )
        
        # Store processed logs in Elasticsearch
        if processed_logs:
            storage_success = await elasticsearch_service.store_logs_batch(processed_logs)
            if not storage_success:
                logger.error("Failed to store logs in Elasticsearch")
            
            # Send logs to WebSocket connections for real-time updates
            await LogService.send_logs_to_websocket(processed_logs)
        
        processed_count = len(processed_logs)
        anomalies_detected = sum(1 for log in processed_logs if log.get("infected", False))
        logger.info(f"Successfully processed {processed_count} logs")

        # Alert managers if anomalies detected
        await LogService.send_anomaly_alert(
            anomalies_detected, processed_logs, batch_id, org_id, db
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
        logger.error(f"Error processing logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to process logs: {str(e)}")

