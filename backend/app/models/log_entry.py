"""
Log Entry Model
Defines the structure for log entries in the system
"""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class LogEntry(BaseModel):
    """Log entry model matching frontend interface"""
    timestamp: str
    ipAddress: str
    apiAccessed: str
    statusCode: int
    infected: bool

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "12:04 7 Oct 2025",
                "ipAddress": "201.12.12.24",
                "apiAccessed": "/api/v1/fetch",
                "statusCode": 200,
                "infected": False
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
