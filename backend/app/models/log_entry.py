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
    ipAddress: str
    apiAccessed: str
    statusCode: int
    infected: bool
    anomaly_score: Optional[float] = None
    anomaly_details: Optional[AnomalyDetails] = None

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "12:04 7 Oct 2025",
                "ipAddress": "201.12.12.24",
                "apiAccessed": "/api/v1/fetch",
                "statusCode": 200,
                "infected": False,
                "anomaly_score": 0.25,
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


class LogEntryResponse(BaseModel):
    """Response model for log entries"""
    logs: list[LogEntry]
    websocket_id: str
    total_count: int
    infected_count: int


class WebSocketMessage(BaseModel):
    """WebSocket message model"""
    type: str
    data: dict
    timestamp: datetime
