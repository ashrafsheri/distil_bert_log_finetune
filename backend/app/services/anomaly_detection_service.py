"""
Anomaly Detection Service
Communicates with the realtime anomaly detection microservice
"""

import httpx
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)

class AnomalyDetectionService:
    """
    Anomaly Detection Service
    Communicates with the realtime anomaly detection microservice
    """
    
    def __init__(self, base_url: str = "http://anomaly-detection:8001"):
        """
        Initialize anomaly detection service client
        
        Args:
            base_url: Base URL of the anomaly detection microservice
            
        Returns:
            None
        """
        self.base_url = base_url
        self.timeout = 30.0  # 30 second timeout

    @staticmethod
    def _normalize_detection_payload(result: Dict[str, Any]) -> Dict[str, Any]:
        details = result.get("details", {})
        if not isinstance(details, dict):
            details = {}

        return {
            "is_anomaly": result.get("is_anomaly", False),
            "anomaly_score": result.get("anomaly_score", 0.0),
            "phase": result.get("phase"),
            "model_type": result.get("model_type"),
            "details": {
                "rule_based": details.get("rule_based", {}),
                "isolation_forest": details.get("isolation_forest", {}),
                "transformer": details.get("transformer", {}),
                "ensemble": details.get("ensemble", {}),
            },
            "detection_status": details.get("detection_status", result.get("detection_status", "scored")),
            "detection_error": details.get("detection_error", result.get("detection_error")),
            "model_version": details.get("model_version", result.get("model_version", "adaptive-v2")),
            "feature_schema_version": details.get("feature_schema_version", result.get("feature_schema_version", "access-log-v1")),
            "incident_id": details.get("incident_id", result.get("incident_id")),
            "incident_type": details.get("incident_type", result.get("incident_type")),
            "incident_bucket_start": details.get("incident_bucket_start", result.get("incident_bucket_start")),
            "calibration": details.get("calibration", result.get("calibration", {})),
            "raw_anomaly_score": details.get("raw_anomaly_score", result.get("raw_anomaly_score", result.get("anomaly_score", 0.0))),
            "student_training_blockers": details.get("student_training_blockers", result.get("student_training_blockers", [])),
        }
    
    async def detect_single_log(self, log_line: str, session_id: Optional[str] = None) -> Optional[Dict]:
        """
        Send single log line to anomaly detection service
        
        Args:
            log_line: Raw log line to analyze
            session_id: Optional session identifier
            
        Returns:
            Anomaly detection result or None if failed
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "log_line": log_line,
                    "session_id": session_id
                }
                
                response = await client.post(
                    f"{self.base_url}/detect",
                    json=payload
                )
                
                if response.status_code == 200:
                    result = response.json()
                    logger.debug(f"Anomaly detection successful for log: {log_line[:50]}...")
                    return result
                else:
                    logger.error(f"Anomaly detection failed with status {response.status_code}: {response.text}")
                    return None
                    
        except httpx.TimeoutException:
            logger.error("Anomaly detection request timed out")
            return None
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return None
    
    async def detect_batch_logs(self, log_lines: List[str], session_id: Optional[str] = None) -> Optional[List[Dict]]:
        """
        Send batch of log lines to anomaly detection service
        
        Args:
            log_lines: List of raw log lines to analyze
            session_id: Optional session identifier
            
        Returns:
            List of anomaly detection results or None if failed
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "log_lines": log_lines,
                    "session_id": session_id
                }
                
                response = await client.post(
                    f"{self.base_url}/detect/batch",
                    json=payload
                )
                
                if response.status_code == 200:
                    result = response.json()
                    logger.debug(f"Batch anomaly detection successful for {len(log_lines)} logs")
                    return result.get("results", [])
                else:
                    logger.error(f"Batch anomaly detection failed with status {response.status_code}: {response.text}")
                    return None
                    
        except httpx.TimeoutException:
            logger.error("Batch anomaly detection request timed out")
            return None
        except Exception as e:
            logger.error(f"Error in batch anomaly detection: {e}")
            return None

    async def detect_structured_log(self, event: Dict[str, Any]) -> Optional[Dict]:
        """Send a structured event to the anomaly detection service."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/detect/structured",
                    json=event,
                )

                if response.status_code == 200:
                    return self._normalize_detection_payload(response.json())

                logger.error(
                    "Structured anomaly detection failed with status %s: %s",
                    response.status_code,
                    response.text,
                )
                return None
        except httpx.TimeoutException:
            logger.error("Structured anomaly detection request timed out")
            return None
        except Exception as e:
            logger.error(f"Error in structured anomaly detection: {e}")
            return None

    async def detect_batch_structured_logs(self, events: List[Dict[str, Any]]) -> Optional[List[Dict]]:
        """Send a batch of structured events to the anomaly detection service."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/detect/batch/structured",
                    json={"events": events},
                )

                if response.status_code == 200:
                    result = response.json()
                    return [self._normalize_detection_payload(item) for item in result.get("results", [])]

                logger.error(
                    "Structured batch anomaly detection failed with status %s: %s",
                    response.status_code,
                    response.text,
                )
                return None
        except httpx.TimeoutException:
            logger.error("Structured batch anomaly detection request timed out")
            return None
        except Exception as e:
            logger.error(f"Error in structured batch anomaly detection: {e}")
            return None

    async def register_or_update_project(
        self,
        *,
        project_id: str,
        project_name: str,
        warmup_threshold: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/internal/projects/register",
                    json={
                        "project_id": project_id,
                        "project_name": project_name,
                        "warmup_threshold": warmup_threshold,
                        "metadata": metadata or {},
                    },
                )
                if response.status_code == 200:
                    return response.json()
                logger.error(
                    "Project registration failed with status %s: %s",
                    response.status_code,
                    response.text,
                )
                return None
        except Exception as e:
            logger.error(f"Error registering project with detector: {e}")
            return None

    async def report_project_ingest_stats(
        self,
        *,
        project_id: str,
        total_records: int,
        parse_failures: int,
        baseline_eligible: int,
        observed_hours: List[int],
        data_quality_incident_open: Optional[bool] = None,
    ) -> Optional[Dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/internal/projects/ingest-stats",
                    json={
                        "project_id": project_id,
                        "total_records": total_records,
                        "parse_failures": parse_failures,
                        "baseline_eligible": baseline_eligible,
                        "observed_hours": observed_hours,
                        "data_quality_incident_open": data_quality_incident_open,
                    },
                )
                if response.status_code == 200:
                    return response.json()
                logger.error(
                    "Project ingest stats sync failed with status %s: %s",
                    response.status_code,
                    response.text,
                )
                return None
        except Exception as e:
            logger.error(f"Error reporting project ingest stats: {e}")
            return None
