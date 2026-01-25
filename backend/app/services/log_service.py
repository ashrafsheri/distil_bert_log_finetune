"""
Log Service
Business logic for log processing and management
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import csv
import io
import logging
import ipaddress
import json
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException

from app.models.log_entry import LogEntry, LogEntryCreate, CorrectLogRequest
from app.models.ip_db import IPDB, IPStatusEnum
from app.models.user_db import UserDB, RoleEnum
from app.services.elasticsearch_service import ElasticsearchService
from app.services.email_service import can_send_alert, mark_alert_sent, send_email
from app.controllers.websocket_controller import send_log_update

logger = logging.getLogger(__name__)


class LogService:
    """Service class for log-related business logic"""
    
    def __init__(self):
        # TODO: Initialize database connection, cache, etc.
        self.logs_storage = []  # Placeholder for actual storage
        self.websocket_connections = {}  # Placeholder for WebSocket management
    
    async def get_latest_logs(self, limit: int = 1000) -> List[LogEntry]:
        """
        Retrieve latest logs from storage
        
        Args:
            limit: Maximum number of logs to return
            
        Returns:
            List of LogEntry objects
        """
        # TODO: Implement actual log retrieval
        # This should:
        # 1. Query database/storage for latest logs
        # 2. Apply any filters or sorting
        # 3. Return LogEntry objects
        
        # Placeholder implementation
        return []
    
    async def create_log_entry(self, log_data: LogEntryCreate) -> LogEntry:
        """
        Create a new log entry
        
        Args:
            log_data: Log entry data
            
        Returns:
            Created LogEntry object
        """
        # TODO: Implement log creation
        # This should:
        # 1. Validate log data
        # 2. Add timestamp
        # 3. Store in database
        # 4. Trigger real-time updates
        
        # Placeholder implementation
        log_entry = LogEntry(
            timestamp=datetime.now().strftime("%H:%M %d %b %Y"),
            ip_address=log_data.ip_address,
            api_accessed=log_data.api_accessed,
            status_code=log_data.status_code,
            infected=log_data.infected
        )
        
        return log_entry
    
    async def process_agent_logs(self, logs: List[dict]) -> int:
        """
        Process logs received from LogShipper Agent
        
        Args:
            logs: List of raw log data from agent
            
        Returns:
            Number of successfully processed logs
        """
        # TODO: Implement agent log processing
        # This should:
        # 1. Parse and validate each log
        # 2. Apply any transformations
        # 3. Store in database
        # 4. Perform anomaly detection
        # 5. Trigger WebSocket updates
        
        # Placeholder implementation
        processed_count = 0
        
        for log_data in logs:
            try:
                # Validate and process log
                # log_entry = await self.create_log_entry(log_data)
                # await self.trigger_realtime_update(log_entry)
                processed_count += 1
            except Exception as e:
                logger.error(f"Error processing log: {e}")
                continue
        
        return processed_count
    
    async def detect_anomalies(self, log_entry: LogEntry) -> bool:
        """
        Detect anomalies in log entry
        
        Args:
            log_entry: Log entry to analyze
            
        Returns:
            True if anomaly detected, False otherwise
        """
        # TODO: Implement anomaly detection logic
        # This should:
        # 1. Apply ML models for anomaly detection
        # 2. Check against known attack patterns
        # 3. Analyze behavioral patterns
        # 4. Return anomaly status
        
        # Placeholder implementation
        return False
    
    async def trigger_realtime_update(self, log_entry: LogEntry, client_id: Optional[str] = None):
        """
        Trigger real-time update via WebSocket
        
        Args:
            log_entry: Log entry to broadcast
            client_id: Specific client ID (None for broadcast)
        """
        # TODO: Implement WebSocket broadcasting
        # This should:
        # 1. Format log entry for WebSocket
        # 2. Send to specific client or broadcast
        # 3. Handle connection errors
        
        # Placeholder implementation
        pass
    
    def generate_websocket_id(self) -> str:
        """
        Generate unique WebSocket ID for client connection
        
        Returns:
            Unique WebSocket ID string
        """
        return str(uuid.uuid4())
    
    async def export_logs_to_csv(self, logs: List[dict]) -> str:
        """
        Export logs to CSV format with anomaly scores for each model
        
        Args:
            logs: List of log dictionaries from Elasticsearch
            
        Returns:
            CSV string content
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write CSV header
        writer.writerow([
            'Timestamp',
            'IP Address',
            'API Accessed',
            'Status Code',
            'Infected',
            'Ensemble Anomaly Score',
            'Rule-Based Detection',
            'Rule-Based Confidence',
            'Rule-Based Attack Types',
            'Isolation Forest Detection',
            'Isolation Forest Score',
            'Transformer Detection',
            'Transformer NLL Score',
            'Transformer Threshold',
            'Transformer Sequence Length'
        ])
        
        # Write log data
        for log in logs:
            anomaly_details = log.get('anomaly_details', {})
            
            # Extract rule-based details
            rule_based = anomaly_details.get('rule_based', {})
            rule_attack = rule_based.get('is_attack', False)
            rule_confidence = rule_based.get('confidence', 0.0)
            rule_attack_types = ', '.join(rule_based.get('attack_types', []))
            
            # Extract isolation forest details
            iso_forest = anomaly_details.get('isolation_forest', {})
            iso_anomaly = iso_forest.get('is_anomaly', 0)
            iso_score = iso_forest.get('score', 0.0)
            
            # Extract transformer details
            transformer = anomaly_details.get('transformer', {})
            trans_anomaly = transformer.get('is_anomaly', 0)
            trans_score = transformer.get('score', 0.0)
            trans_threshold = transformer.get('threshold', 0.0)
            trans_seq_len = transformer.get('sequence_length', 0)
            
            # Extract ensemble details
            ensemble = anomaly_details.get('ensemble', {})
            ensemble_score = ensemble.get('score', 0.0)
            
            writer.writerow([
                log.get('timestamp', ''),
                log.get('ip_address', ''),
                log.get('api_accessed', ''),
                log.get('status_code', ''),
                log.get('infected', False),
                ensemble_score,
                'Yes' if rule_attack else 'No',
                rule_confidence,
                rule_attack_types,
                'Yes' if iso_anomaly == 1 else 'No',
                iso_score,
                'Yes' if trans_anomaly == 1 else 'No',
                trans_score,
                trans_threshold,
                trans_seq_len
            ])
        
        return output.getvalue()
    
    async def get_log_statistics(self) -> dict:
        """
        Get log statistics for dashboard
        
        Returns:
            Dictionary with log statistics
        """
        # TODO: Implement statistics calculation
        # This should:
        # 1. Count total logs
        # 2. Count infected/threat logs
        # 3. Calculate threat rate
        # 4. Return formatted statistics
        
        # Placeholder implementation
        return {
            "total_logs": 0,
            "infected_logs": 0,
            "threat_rate": 0.0,
            "last_updated": datetime.now().isoformat()
        }

    async def correct_log_status(
        self,
        request: CorrectLogRequest,
        user_info: Dict[str, Any],
        db: AsyncSession,
        elasticsearch_service: ElasticsearchService
    ) -> Dict[str, Any]:
        """
        Correct log status for an IP address.

        Args:
            request: CorrectLogRequest with ip and status
            user_info: User information dict with email, role, org_id
            db: Database session
            elasticsearch_service: Elasticsearch service instance

        Returns:
            Dict with correction results
        """
        # Extract user information
        user_email = user_info.get("email", "unknown")
        user_role = user_info.get("role", "unknown")
        org_id = user_info["org_id"]

        # Validate IP address format
        try:
            ipaddress.ip_address(request.ip)
        except ValueError:
            raise ValueError("Invalid IP address format")

        # Validate and normalize status
        status_lower = request.status.lower()
        if status_lower not in ["clean", "malicious"]:
            raise ValueError("Status must be either 'clean' or 'malicious'")

        status_enum = IPStatusEnum.CLEAN if status_lower == "clean" else IPStatusEnum.MALICIOUS
        infected = status_enum == IPStatusEnum.MALICIOUS

        # Check if IP already exists in database for this org
        async with db.begin():
            result = await db.execute(select(IPDB).where(IPDB.ip == request.ip, IPDB.org == org_id))
            existing_ip = result.scalar_one_or_none()

            # Prepare database operation
            if existing_ip:
                # Update existing IP record
                old_status = existing_ip.status.value
                existing_ip.status = status_enum

                logger.warning(
                    f"[HUMAN CORRECTION] User {user_email} ({user_role}) changed IP {request.ip} "
                    f"status from '{old_status}' to '{request.status}' for org {org_id}. "
                    f"This overrides model predictions."
                )
            else:
                # Create new IP record
                new_ip = IPDB(
                    ip=request.ip,
                    status=status_enum,
                    org=org_id
                )
                db.add(new_ip)

                logger.warning(
                    f"[HUMAN CORRECTION] User {user_email} ({user_role}) marked IP {request.ip} "
                    f"as '{request.status}' for org {org_id}. This is a new manual classification."
                )

        # Update all logs for this IP in Elasticsearch
        update_result = await elasticsearch_service.update_logs_by_ip(
            ip_address=request.ip,
            infected=infected,
            org_id=org_id
        )

        # Handle Elasticsearch update results
        if update_result["status"] == "error":
            logger.error(
                f"[HUMAN CORRECTION] Failed to update logs in Elasticsearch for IP {request.ip}: "
                f"{update_result.get('message')}"
            )
            return {
                "message": "IP status updated in database, but Elasticsearch update failed",
                "ip": request.ip,
                "status": request.status,
                "database_updated": True,
                "elasticsearch_updated": False,
                "elasticsearch_error": update_result.get("message"),
                "logs_updated_count": 0,
                "corrected_by": user_email
            }

        logs_count = update_result.get("update_count", 0)
        logger.info(
            f"[HUMAN CORRECTION] Successfully updated {logs_count} log(s) in Elasticsearch "
            f"for IP {request.ip} to status '{request.status}' by user {user_email}"
        )

        return {
            "message": "IP status updated successfully",
            "ip": request.ip,
            "status": request.status,
            "database_updated": True,
            "elasticsearch_updated": True,
            "logs_updated_count": logs_count,
            "corrected_by": user_email
        }

    @staticmethod
    def parse_fluent_bit_request(body: bytes) -> List[Dict[str, Any]]:
        """
        Parse the raw request body from Fluent Bit.

        Args:
            body: Raw request body bytes

        Returns:
            List of log records

        Raises:
            HTTPException: If request format is invalid
        """
        try:
            request_data = json.loads(body)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON in request body: {str(e)}")

        if not isinstance(request_data, list):
            raise HTTPException(status_code=400, detail="Request must be an array of log records")

        return request_data

    @staticmethod
    def extract_raw_logs_from_records(records: List[Any]) -> List[str]:
        """
        Extract raw log strings from Fluent Bit records.

        Args:
            records: List of records from Fluent Bit (dicts with 'log' key or strings)

        Returns:
            List of raw log strings
        """
        raw_logs = []

        for record in records:
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

        return raw_logs

    @staticmethod
    async def get_ip_status_map(unique_ips: set, org_id: str, db: AsyncSession) -> Dict[str, bool]:
        """
        Query IP database for status overrides for given IPs.

        Args:
            unique_ips: Set of unique IP addresses
            org_id: Organization ID
            db: Database session

        Returns:
            Dict mapping IP addresses to infected status (True for malicious)
        """
        ip_status_map = {}

        if not unique_ips:
            return ip_status_map

        try:
            result = await db.execute(
                select(IPDB).where(IPDB.ip.in_(list(unique_ips)), IPDB.org == org_id)
            )
            ip_records = result.scalars().all()

            for ip_record in ip_records:
                # Map status to infected boolean: malicious = True, clean = False
                ip_status_map[ip_record.ip] = ip_record.status == IPStatusEnum.MALICIOUS

            logger.debug(f"Found {len(ip_status_map)} IPs in IP table out of {len(unique_ips)} unique IPs for org {org_id}")

        except Exception as e:
            logger.error(f"Error querying IP table: {e}")

        return ip_status_map

    @staticmethod
    def format_log_for_storage(
        parsed_log: Dict[str, Any],
        raw_log: str,
        anomaly_result: Dict[str, Any],
        ip_status_map: Dict[str, bool],
        batch_id: str,
        org_id: str
    ) -> Dict[str, Any]:
        """
        Format a parsed log for Elasticsearch storage.

        Args:
            parsed_log: Parsed log data from log parser
            raw_log: Original raw log string
            anomaly_result: Anomaly detection result
            ip_status_map: IP status override map
            batch_id: Batch identifier
            org_id: Organization ID

        Returns:
            Formatted log dict for Elasticsearch
        """
        ip_address = parsed_log["ip_address"]
        infected_status = anomaly_result.get("is_anomaly", False)

        # Override infected status if IP is in the IP table
        if ip_address in ip_status_map:
            infected_status = ip_status_map[ip_address]
            logger.debug(f"Overriding infected status for IP {ip_address} to {infected_status} based on IP table")

        # Format for storage - use original ISO timestamp for Elasticsearch
        formatted_log = {
            "timestamp": parsed_log["timestamp"],  # Keep original ISO format for Elasticsearch
            "ip_address": ip_address,
            "api_accessed": parsed_log["path"],
            "status_code": parsed_log["status_code"],
            "infected": infected_status,
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
            "source": "fluent_bit",
            "org_id": org_id  # Add organization ID to the log
        }

        return formatted_log

    @staticmethod
    def convert_log_for_websocket(log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert Elasticsearch log format to WebSocket format (camelCase).

        Args:
            log: Log in Elasticsearch format

        Returns:
            Log in WebSocket format
        """
        return {
            "timestamp": log.get("timestamp", ""),
            "ipAddress": log.get("ip_address", ""),
            "apiAccessed": log.get("api_accessed", ""),
            "statusCode": log.get("status_code", 0),
            "infected": log.get("infected", False),
            "anomaly_score": log.get("anomaly_score", 0.0),
            "anomaly_details": log.get("anomaly_details", {})
        }

    @staticmethod
    async def send_anomaly_alert(
        anomalies_detected: int,
        processed_logs: List[Dict[str, Any]],
        batch_id: str,
        org_id: str,
        db: AsyncSession
    ) -> None:
        """
        Send email alert for detected anomalies.

        Args:
            anomalies_detected: Number of anomalies detected
            processed_logs: List of processed logs
            batch_id: Batch identifier
            org_id: Organization ID
            db: Database session
        """
        try:
            if anomalies_detected > 0 and can_send_alert():
                # Fetch manager emails for this organization
                result = await db.execute(
                    select(UserDB).where(UserDB.role == RoleEnum.MANAGER, UserDB.org_id == org_id)
                )
                managers = result.scalars().all()
                recipients = [u.email for u in managers if getattr(u, 'enabled', True)]

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

    @staticmethod
    async def process_parsed_logs_batch(
        parsed_logs_data: List[Dict[str, Any]],
        anomaly_results: List[Dict[str, Any]],
        ip_status_map: Dict[str, bool],
        batch_id: str,
        org_id: str
    ) -> List[Dict[str, Any]]:
        """
        Process a batch of parsed logs into formatted logs for storage.

        Args:
            parsed_logs_data: List of parsed log data
            anomaly_results: List of anomaly detection results
            ip_status_map: IP status override map
            batch_id: Batch identifier
            org_id: Organization ID

        Returns:
            List of formatted logs for storage
        """
        processed_logs = []

        for log_data in parsed_logs_data:
            try:
                parsed_log = log_data["parsed_log"]
                raw_log = log_data["raw_log"]
                i = log_data["anomaly_index"]

                # Get anomaly result for this log
                anomaly_result = anomaly_results[i] if i < len(anomaly_results) else {
                    "is_anomaly": False,
                    "anomaly_score": 0.0,
                    "details": {}
                }

                formatted_log = LogService.format_log_for_storage(
                    parsed_log, raw_log, anomaly_result, ip_status_map, batch_id, org_id
                )

                processed_logs.append(formatted_log)

            except Exception as e:
                logger.error(f"Error processing individual log: {e}")
                continue

        return processed_logs

    @staticmethod
    async def send_logs_to_websocket(processed_logs: List[Dict[str, Any]]) -> None:
        """
        Send processed logs to WebSocket connections for real-time updates.

        Args:
            processed_logs: List of processed logs
        """
        for log in processed_logs:
            try:
                websocket_log = LogService.convert_log_for_websocket(log)
                await send_log_update(websocket_log)
                logger.debug(f"Sent log to WebSocket: {websocket_log}")
                logger.info(f"WebSocket log sent - IP: {websocket_log.get('ipAddress')}, API: {websocket_log.get('apiAccessed')}")
            except Exception as e:
                logger.error(f"Error sending log to WebSocket: {e}")
