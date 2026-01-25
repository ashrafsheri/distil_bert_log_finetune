"""
Log Processing Utilities
Helper functions for processing logs from various sources including Fluent Bit
"""

import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.ip_db import IPDB, IPStatusEnum
from app.models.user_db import UserDB, RoleEnum
from app.services.email_service import can_send_alert, mark_alert_sent, send_email
from app.controllers.websocket_controller import send_log_update
import asyncio

logger = logging.getLogger(__name__)


class LogProcessingUtils:
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
                logger.error(f"Error sending log to WebSocket: {e}")</content>
