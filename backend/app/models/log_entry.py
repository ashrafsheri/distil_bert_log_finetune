"""
Log Entry Model
Defines the structure for log entries in the system
"""

from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime


class AnomalyDetails(BaseModel):
    """Detailed anomaly detection information from ensemble models"""
    rule_based: Optional[Dict[str, Any]] = None
    isolation_forest: Optional[Dict[str, Any]] = None
    transformer: Optional[Dict[str, Any]] = None
    ensemble: Optional[Dict[str, Any]] = None


class LogEntry(BaseModel):
    """Log entry model matching frontend interface"""
    timestamp: str
    eventTime: Optional[str] = None
    ingestTime: Optional[str] = None
    ipAddress: str
    apiAccessed: str
    statusCode: int
    infected: bool
    anomaly_score: Optional[float] = None
    anomaly_details: Optional[AnomalyDetails] = None
    org_id: Optional[str] = None
    parseStatus: Optional[str] = None
    parseError: Optional[str] = None
    detectionStatus: Optional[str] = None
    detectionError: Optional[str] = None
    incidentId: Optional[str] = None
    incidentType: Optional[str] = None
    incidentGroupedEventCount: Optional[int] = None
    incidentReason: Optional[str] = None
    topContributingSignals: Optional[list[str]] = None
    normalizedTemplate: Optional[str] = None
    sessionKeyHash: Optional[str] = None
    modelVersion: Optional[str] = None
    featureSchemaVersion: Optional[str] = None
    detectorPhase: Optional[str] = None
    modelType: Optional[str] = None
    rawAnomalyScore: Optional[float] = None
    calibration: Optional[Dict[str, Any]] = None
    trafficClass: Optional[str] = None
    baselineEligible: Optional[bool] = None
    decisionReason: Optional[str] = None
    policyScore: Optional[float] = None
    finalDecision: Optional[str] = None
    componentStatus: Optional[Dict[str, Any]] = None
    thresholdSource: Optional[str] = None
    thresholdFittedAt: Optional[str] = None
    calibrationSampleCount: Optional[int] = None
    scoreNormalizationVersion: Optional[str] = None
    unknownTemplateRatio: Optional[float] = None

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "12:04 7 Oct 2025",
                "eventTime": "2025-10-07T12:04:00Z",
                "ingestTime": "2025-10-07T12:04:01Z",
                "ipAddress": "201.12.12.24",
                "apiAccessed": "/api/v1/fetch",
                "statusCode": 200,
                "infected": False,
                "anomaly_score": 0.25,
                "parseStatus": "parsed",
                "detectionStatus": "scored",
                "incidentId": "proj-1:/login:203.0.113.4:2025-10-07T12:00:00Z",
                "incidentGroupedEventCount": 4,
                "incidentReason": "known_attack_policy",
                "topContributingSignals": ["rule:path_traversal", "rule:command_injection"],
                "normalizedTemplate": "GET /api/v1/fetch HTTP/1.1 200",
                "modelVersion": "multi-tenant-v1",
                "featureSchemaVersion": "access-log-v1",
                "detectorPhase": "warmup",
                "modelType": "teacher",
                "rawAnomalyScore": 0.31,
                "trafficClass": "user_traffic",
                "baselineEligible": True,
                "decisionReason": "behavioral_anomaly",
                "policyScore": 0.0,
                "finalDecision": "threat_detected",
                "componentStatus": {"rule_based": "active", "transformer": "active", "isolation_forest": "not_fitted"},
                "thresholdSource": "holdout_calibration",
                "thresholdFittedAt": "2025-10-07T12:00:00Z",
                "calibrationSampleCount": 128,
                "scoreNormalizationVersion": "hybrid-v1",
                "unknownTemplateRatio": 0.1,
                "calibration": {"threshold": 0.58, "calibrated_score": 0.25},
                "anomaly_details": {
                    "rule_based": {"is_attack": False, "confidence": 0.0},
                    "isolation_forest": {"is_anomaly": 0, "score": 0.3},
                    "transformer": {"is_anomaly": 0, "score": 4.5},
                    "ensemble": {"score": 0.25, "votes": {"rule": 0, "iso": 0, "transformer": 0}}
                }
            }
        }


class LogEntryCreate(BaseModel):
    """Model for creating new log entries"""
    ipAddress: str
    apiAccessed: str
    statusCode: int
    infected: bool = False
    org_id : Optional[str] = None


class CorrectLogRequest(BaseModel):
    """Request model for correctLog endpoint"""
    ip: str
    status: str  # "clean" or "malicious"


class LogEntryResponse(BaseModel):
    """Response model for log entries"""
    logs: list[LogEntry]
    websocket_id: str
    total_count: int
    infected_count: int
    safe_count: int
    threat_rate: float
    parse_failure_count: int = 0
    detection_failure_count: int = 0
    incident_count: int = 0
    skipped_count: int = 0


class WebSocketMessage(BaseModel):
    """WebSocket message model"""
    type: str
    data: dict
    timestamp: datetime
