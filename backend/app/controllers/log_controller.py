"""
Log Controller
Handles log-related API endpoints
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse
from typing import List
import uuid
import asyncio
import json
import logging

from app.models.log_entry import LogEntry, LogEntryResponse, AnomalyDetails
from app.services.log_service import LogService
from app.services.elasticsearch_service import ElasticsearchService
from app.services.log_parser_service import LogParserService
from app.services.anomaly_detection_service import AnomalyDetectionService
from app.controllers.websocket_controller import send_log_update
from app.utils.firebase_auth import get_current_user
from app.utils.permissions import check_permission
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.utils.database import get_db
from app.models.user_db import UserDB, RoleEnum
from app.services.email_service import can_send_alert, mark_alert_sent, send_email

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
        # Cap limit to 100 max
        safe_limit = min(max(limit, 1), 100)
        safe_offset = max(offset, 0)
        # Fetch logs from Elasticsearch with pagination
        result = await elasticsearch_service.get_logs(limit=safe_limit, offset=safe_offset)
        # Convert to LogEntry format for frontend
        logs = []
        for log_data in result["logs"]:
            # Extract anomaly_details if present
            anomaly_details = log_data.get("anomaly_details")
            if anomaly_details and isinstance(anomaly_details, dict):
                anomaly_details_obj = AnomalyDetails(
                    rule_based=anomaly_details.get("rule_based"),
                    isolation_forest=anomaly_details.get("isolation_forest"),
                    transformer=anomaly_details.get("transformer"),
                    ensemble=anomaly_details.get("ensemble")
                )
            else:
                anomaly_details_obj = None
            
            log_entry = LogEntry(
                timestamp=log_data.get("timestamp", ""),
                ipAddress=log_data.get("ip_address", ""),
                apiAccessed=log_data.get("api_accessed", ""),
                statusCode=log_data.get("status_code", 0),
                infected=log_data.get("infected", False),
                anomaly_score=log_data.get("anomaly_score"),
                anomaly_details=anomaly_details_obj
            )
            logs.append(log_entry)
        
        # Generate WebSocket ID for real-time updates
        websocket_id = str(uuid.uuid4())
        
        return LogEntryResponse(
            logs=logs,
            websocket_id=websocket_id,
            total_count=result.get("total", 0),
            infected_count=sum(1 for l in logs if l.infected)
        )
        
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
            ip=ip,
            api=api,
            status_code=status_code,
            infected=infected,
            from_datetime=from_dt,
            to_datetime=to_dt,
            limit=safe_limit,
            offset=safe_offset,
        )

        # Convert to LogEntry format for frontend
        logs: List[LogEntry] = []
        for log_data in result["logs"]:
            # Extract anomaly_details if present
            anomaly_details = log_data.get("anomaly_details")
            if anomaly_details and isinstance(anomaly_details, dict):
                anomaly_details_obj = AnomalyDetails(
                    rule_based=anomaly_details.get("rule_based"),
                    isolation_forest=anomaly_details.get("isolation_forest"),
                    transformer=anomaly_details.get("transformer"),
                    ensemble=anomaly_details.get("ensemble")
                )
            else:
                anomaly_details_obj = None
            
            logs.append(
                LogEntry(
                    timestamp=log_data.get("timestamp", ""),
                    ipAddress=log_data.get("ip_address", ""),
                    apiAccessed=log_data.get("api_accessed", ""),
                    statusCode=log_data.get("status_code", 0),
                    infected=log_data.get("infected", False),
                    anomaly_score=log_data.get("anomaly_score"),
                    anomaly_details=anomaly_details_obj
                )
            )

        websocket_id = str(uuid.uuid4())
        return LogEntryResponse(
            logs=logs,
            websocket_id=websocket_id,
            total_count=result.get("total", 0),
            infected_count=sum(1 for l in logs if l.infected),
        )
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
        from datetime import datetime
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

@router.post("/agent/sendLogs")
async def receive_fluent_bit_logs(
    request: Request,
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    log_parser_service: LogParserService = Depends(get_log_parser_service),
    anomaly_detection_service: AnomalyDetectionService = Depends(get_anomaly_detection_service),
    db: AsyncSession = Depends(get_db)
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
        raw_logs = []
        print("Recieved Log")
        # Parse the raw request body
        body = await request.body()
        request_data = json.loads(body)
        
        # Process Fluent Bit records
        if not isinstance(request_data, list):
            raise HTTPException(status_code=400, detail="Request must be an array of log records")
        
        for record in request_data:
            if isinstance(record, dict) and 'log' in record:
                logger.debug(f"Processing log record: {record}")
                raw_logs.append(record['log'])
            elif isinstance(record, str):
                # Direct string log
                logger.debug(f"Processing string log: {record}")
                raw_logs.append(record)
            else:
                # Skip invalid records but continue processing
                logger.debug(f"Skipping invalid record: {record}")
                continue
        
        if not raw_logs:
            raise HTTPException(status_code=400, detail="No valid logs found in request")
        
        logger.info(f"Processing {len(raw_logs)} logs from Fluent Bit")
        
        # Process logs through anomaly detection
        anomaly_results = await anomaly_detection_service.detect_batch_logs(
            log_lines=raw_logs,
            session_id=f"fluent_bit_{batch_id}"
        )
        print(anomaly_results)
        
        if anomaly_results is None:
            logger.warning("Anomaly detection failed, processing logs without detection")
            anomaly_results = [{"is_anomaly": False, "anomaly_score": 0.0, "details": {}}] * len(raw_logs)
        
        # Parse and format logs for storage
        processed_logs = []
        for i, raw_log in enumerate(raw_logs):
            try:
                # Parse Apache log
                parsed_log = log_parser_service.parse_apache_log(raw_log)
                if parsed_log is None:
                    logger.warning(f"Could not parse log: {raw_log[:100]}...")
                    continue
                
                # Get anomaly result for this log
                anomaly_result = anomaly_results[i] if i < len(anomaly_results) else {
                    "is_anomaly": False, 
                    "anomaly_score": 0.0, 
                    "details": {}
                }
                
                # Format for storage - use original ISO timestamp for Elasticsearch
                formatted_log = {
                    "timestamp": parsed_log["timestamp"],  # Keep original ISO format for Elasticsearch
                    "ip_address": parsed_log["ip_address"],
                    "api_accessed": parsed_log["path"],
                    "status_code": parsed_log["status_code"],
                    "infected": anomaly_result.get("is_anomaly", False),
                    "anomaly_score": anomaly_result.get("anomaly_score", 0.0),
                    "anomaly_details": {
                        "rule_based": anomaly_result.get("details", {}).get("rule_based", {}),
                        "isolation_forest": anomaly_result.get("details", {}).get("isolation_forest", {}),
                        "transformer": anomaly_result.get("details", {}).get("transformer", {}),
                        "ensemble": anomaly_result.get("details", {}).get("ensemble", {})
                    },
                    "raw_log": raw_log,
                    "method": parsed_log.get("method", ""),
                    "protocol": parsed_log.get("protocol", ""),
                    "size": parsed_log.get("size", 0),
                    "batch_id": batch_id,
                    "source": "fluent_bit"
                }
                
                processed_logs.append(formatted_log)
                
            except Exception as e:
                logger.error(f"Error processing individual log: {e}")
                continue
        
        # Store processed logs in Elasticsearch
        if processed_logs:
            storage_success = await elasticsearch_service.store_logs_batch(processed_logs)
            if not storage_success:
                logger.error("Failed to store logs in Elasticsearch")
            
            # Send logs to WebSocket connections for real-time updates
            for log in processed_logs:
                try:
                    # Convert to frontend format for WebSocket (camelCase to match frontend)
                    websocket_log = {
                        "timestamp": log.get("timestamp", ""),
                        "ipAddress": log.get("ip_address", ""),
                        "apiAccessed": log.get("api_accessed", ""),
                        "statusCode": log.get("status_code", 0),
                        "infected": log.get("infected", False),
                        "anomaly_score": log.get("anomaly_score", 0.0),
                        "anomaly_details": log.get("anomaly_details", {})
                    }
                    await send_log_update(websocket_log)
                    logger.debug(f"Sent log to WebSocket: {websocket_log}")
                    print(f"📤 WebSocket log sent - IP: {websocket_log.get('ipAddress')}, API: {websocket_log.get('apiAccessed')}")
                except Exception as e:
                    logger.error(f"Error sending log to WebSocket: {e}")
        
        processed_count = len(processed_logs)
        anomalies_detected = sum(1 for log in processed_logs if log.get("infected", False))
        logger.info(f"Successfully processed {processed_count} logs")

        # Alert admins if anomalies detected and cooldown allows
        try:
            if anomalies_detected > 0 and can_send_alert():
                # Fetch admin emails
                result = await db.execute(select(UserDB).where(UserDB.role == RoleEnum.ADMIN))
                admins = result.scalars().all()
                recipients = [u.email for u in admins if getattr(u, 'enabled', True)]
                if recipients:
                    example = next((l for l in processed_logs if l.get("infected", False)), None)
                    subject = f"LogGuard Alert: {anomalies_detected} anomalous log(s) detected"
                    body_lines = [
                        f"Anomaly summary:",
                        f"- Batch ID: {batch_id}",
                        f"- Anomalies detected: {anomalies_detected}",
                    ]
                    if example:
                        body_lines += [
                            "",
                            "Example:",
                            f"Time: {example.get('timestamp','')}",
                            f"IP: {example.get('ip_address','')}",
                            f"API: {example.get('api_accessed','')}",
                            f"Status: {example.get('status_code','')}",
                            f"Score: {example.get('anomaly_score','')}",
                        ]
                    body = "\n".join(body_lines)
                    # Send email (best-effort)
                    await asyncio.to_thread(send_email, subject, body, recipients)
                    mark_alert_sent()
        except Exception as alert_err:
            logger.warning(f"Failed to send anomaly alert email: {alert_err}")
        
        response = {
            "message": "Logs received and processed successfully",
            "batch_id": batch_id,
            "processed_count": processed_count,
            "anomalies_detected": anomalies_detected,
            "status": "success",
            "source": "fluent_bit"
        }
        
        processed_logs.clear()
        return response
        
    except Exception as e:
        logger.error(f"Error processing logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to process logs: {str(e)}")

