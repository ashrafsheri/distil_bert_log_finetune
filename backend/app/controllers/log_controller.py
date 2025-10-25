"""
Log Controller
Handles log-related API endpoints
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from typing import List
import uuid
import json
import logging

from app.models.log_entry import LogEntry, LogEntryResponse
from app.services.log_service import LogService
from app.services.elasticsearch_service import ElasticsearchService
from app.services.log_parser_service import LogParserService
from app.services.anomaly_detection_service import AnomalyDetectionService
from app.controllers.websocket_controller import send_log_update

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
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service)
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
        # Fetch logs from Elasticsearch
        print("Fetching logs")
        result = await elasticsearch_service.get_logs(limit=limit, offset=offset)
        print("Logs fetched")
        # Convert to LogEntry format for frontend
        logs = []
        for log_data in result["logs"]:
            log_entry = LogEntry(
                timestamp=log_data.get("timestamp", ""),
                ipAddress=log_data.get("ip_address", ""),
                apiAccessed=log_data.get("api_accessed", ""),
                statusCode=log_data.get("status_code", 0),
                infected=log_data.get("infected", False)
            )
            logs.append(log_entry)
        
        # Generate WebSocket ID for real-time updates
        websocket_id = str(uuid.uuid4())
        
        # Get statistics - use accurate counts from count API
        stats = await elasticsearch_service.get_stats()
        
        return LogEntryResponse(
            logs=logs,
            websocket_id=websocket_id,
            total_count=stats["total_logs"],  # Use accurate count from stats
            infected_count=stats["anomaly_logs"]
        )
        
    except Exception as e:
        logger.error(f"Error fetching logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch logs: {str(e)}")

@router.post("/agent/sendLogs")
async def receive_fluent_bit_logs(
    request: Request,
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service),
    log_parser_service: LogParserService = Depends(get_log_parser_service),
    anomaly_detection_service: AnomalyDetectionService = Depends(get_anomaly_detection_service)
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
        
        logger.info(f"Successfully processed {len(processed_logs)} logs")
        processed_logs = []
        return {
            "message": "Logs received and processed successfully",
            "batch_id": batch_id,
            "processed_count": len(processed_logs),
            "anomalies_detected": sum(1 for log in processed_logs if log.get("infected", False)),
            "status": "success",
            "source": "fluent_bit"
        }
        
    except Exception as e:
        logger.error(f"Error processing logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to process logs: {str(e)}")

@router.get("/anomalies")
async def get_anomaly_logs(
    limit: int = 100,
    offset: int = 0,
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service)
):
    """
    Get only anomaly logs from Elasticsearch
    
    Args:
        limit: Maximum number of logs to return (default: 100)
        offset: Number of logs to skip (default: 0)
        
    Returns:
        List of anomaly logs
    """
    try:
        result = await elasticsearch_service.get_anomaly_logs(limit=limit, offset=offset)
        
        # Convert to LogEntry format for frontend
        logs = []
        for log_data in result["logs"]:
            # Extract anomaly details if available
            anomaly_details = None
            anomaly_score = log_data.get("anomaly_score", 0.0)
            
            if log_data.get("anomaly_details"):
                from app.models.log_entry import AnomalyDetails
                anomaly_details = AnomalyDetails(
                    rule_based=log_data["anomaly_details"].get("rule_based"),
                    isolation_forest=log_data["anomaly_details"].get("isolation_forest"),
                    transformer=log_data["anomaly_details"].get("transformer"),
                    ensemble=log_data["anomaly_details"].get("ensemble")
                )
            
            log_entry = LogEntry(
                timestamp=log_data.get("timestamp", ""),
                ipAddress=log_data.get("ip_address", ""),
                apiAccessed=log_data.get("api_accessed", ""),
                statusCode=log_data.get("status_code", 0),
                infected=log_data.get("infected", False),
                anomaly_score=anomaly_score,
                anomaly_details=anomaly_details
            )
            logs.append(log_entry)
        
        return {
            "logs": logs,
            "total": result["total"],
            "offset": offset,
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"Error fetching anomaly logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch anomaly logs: {str(e)}")

@router.get("/stats")
async def get_log_stats(
    elasticsearch_service: ElasticsearchService = Depends(get_elasticsearch_service)
):
    """
    Get log statistics from Elasticsearch
    
    Returns:
        Log statistics including total logs, anomalies, etc.
    """
    try:
        stats = await elasticsearch_service.get_stats()
        return stats
        
    except Exception as e:
        logger.error(f"Error fetching log stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch log stats: {str(e)}")

@router.get("/health/anomaly-detection")
async def check_anomaly_detection_health(
    anomaly_detection_service: AnomalyDetectionService = Depends(get_anomaly_detection_service)
):
    """
    Check health status of anomaly detection service
    
    Returns:
        Health status of anomaly detection service
    """
    try:
        health_status = await anomaly_detection_service.get_health_status()
        if health_status is None:
            raise HTTPException(status_code=503, detail="Anomaly detection service unavailable")
        
        return health_status
        
    except Exception as e:
        logger.error(f"Error checking anomaly detection health: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to check anomaly detection health: {str(e)}")
