"""
Log Serializer
Handles serialization logic for log-related responses
"""

import uuid
from typing import List, Dict, Any
from app.models.log_entry import LogEntry, LogEntryResponse, AnomalyDetails


class LogSerializer:
    @staticmethod
    def convert_elasticsearch_logs_to_entries(logs_data: List[Dict[str, Any]]) -> List[LogEntry]:
        """Convert raw Elasticsearch log data to LogEntry objects"""
        logs = []
        for log_data in logs_data:
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
        return logs

    @staticmethod
    def build_log_response(logs_data: List[Dict[str, Any]], total_count: int) -> LogEntryResponse:
        """Build LogEntryResponse from raw Elasticsearch data"""
        logs = LogSerializer.convert_elasticsearch_logs_to_entries(logs_data)
        websocket_id = str(uuid.uuid4())
        infected_count = sum(1 for l in logs if l.infected)
        return LogEntryResponse(
            logs=logs,
            websocket_id=websocket_id,
            total_count=total_count,
            infected_count=infected_count
        )

    @staticmethod
    def serialize_fluent_bit_response(
        message: str,
        batch_id: str,
        processed_count: int,
        anomalies_detected: int,
        status: str = "success",
        source: str = "fluent_bit"
    ) -> Dict[str, Any]:
        """
        Serialize response for Fluent Bit log processing.

        Args:
            message: Response message
            batch_id: Batch identifier
            processed_count: Number of logs processed
            anomalies_detected: Number of anomalies detected
            status: Response status
            source: Log source

        Returns:
            Serialized response dict
        """
        return {
            "message": message,
            "batch_id": batch_id,
            "processed_count": processed_count,
            "anomalies_detected": anomalies_detected,
            "status": status,
            "source": source
        }

    @staticmethod
    def serialize_parsed_log_data(
        parsed_log: Dict[str, Any],
        raw_log: str,
        anomaly_index: int
    ) -> Dict[str, Any]:
        """
        Serialize parsed log data for batch processing.

        Args:
            parsed_log: Parsed log dictionary
            raw_log: Original raw log string
            anomaly_index: Index in anomaly results array

        Returns:
            Serialized log data dict
        """
        return {
            "parsed_log": parsed_log,
            "raw_log": raw_log,
            "anomaly_index": anomaly_index
        }
