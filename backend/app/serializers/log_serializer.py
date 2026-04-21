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
                eventTime=log_data.get("event_time") or log_data.get("timestamp"),
                ingestTime=log_data.get("ingest_time") or log_data.get("created_at"),
                ipAddress=log_data.get("ip_address") or "",
                apiAccessed=log_data.get("api_accessed", ""),
                statusCode=log_data.get("status_code", 0),
                infected=log_data.get("infected", False),
                anomaly_score=log_data.get("anomaly_score"),
                anomaly_details=anomaly_details_obj,
                org_id=log_data.get("org_id"),
                parseStatus=log_data.get("parse_status"),
                parseError=log_data.get("parse_error"),
                detectionStatus=log_data.get("detection_status"),
                detectionError=log_data.get("detection_error"),
                incidentId=log_data.get("incident_id"),
                incidentType=log_data.get("incident_type"),
                incidentGroupedEventCount=log_data.get("incident_grouped_event_count"),
                incidentReason=log_data.get("incident_reason"),
                topContributingSignals=log_data.get("top_contributing_signals"),
                normalizedTemplate=log_data.get("normalized_template"),
                sessionKeyHash=log_data.get("session_key_hash"),
                modelVersion=log_data.get("model_version"),
                featureSchemaVersion=log_data.get("feature_schema_version"),
                detectorPhase=log_data.get("detector_phase"),
                modelType=log_data.get("model_type"),
                rawAnomalyScore=log_data.get("raw_anomaly_score"),
                calibration=log_data.get("calibration"),
                trafficClass=log_data.get("traffic_class"),
                baselineEligible=log_data.get("baseline_eligible"),
                decisionReason=log_data.get("decision_reason"),
                policyScore=log_data.get("policy_score"),
                finalDecision=log_data.get("final_decision"),
                componentStatus=log_data.get("component_status"),
                thresholdSource=log_data.get("threshold_source"),
                thresholdFittedAt=log_data.get("threshold_fitted_at"),
                calibrationSampleCount=log_data.get("calibration_sample_count"),
                scoreNormalizationVersion=log_data.get("score_normalization_version"),
                unknownTemplateRatio=log_data.get("unknown_template_ratio"),
            )
            logs.append(log_entry)
        return logs

    @staticmethod
    def build_log_response(
        logs_data: List[Dict[str, Any]],
        total_count: int,
        infected_count: int | None = None,
        parse_failure_count: int = 0,
        detection_failure_count: int = 0,
        incident_count: int = 0,
        skipped_count: int = 0,
    ) -> LogEntryResponse:
        """Build LogEntryResponse from raw Elasticsearch data"""
        logs = LogSerializer.convert_elasticsearch_logs_to_entries(logs_data)
        websocket_id = str(uuid.uuid4())
        aggregate_infected_count = infected_count
        if aggregate_infected_count is None:
            aggregate_infected_count = sum(1 for l in logs if l.infected)
        safe_count = max(total_count - aggregate_infected_count, 0)
        threat_rate = round((aggregate_infected_count / total_count) * 100, 1) if total_count else 0.0
        return LogEntryResponse(
            logs=logs,
            websocket_id=websocket_id,
            total_count=total_count,
            infected_count=aggregate_infected_count,
            safe_count=safe_count,
            threat_rate=threat_rate,
            parse_failure_count=parse_failure_count,
            detection_failure_count=detection_failure_count,
            incident_count=incident_count,
            skipped_count=skipped_count,
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
