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
    ip_address: str
    api_accessed: str
    status_code: int
    infected: bool

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "12:04 7 Oct 2025",
                "ip_address": "201.12.12.24",
                "api_accessed": "/api/v1/fetch",
                "status_code": 200,
                "infected": False
            }
        }


class LogEntryCreate(BaseModel):
    """Model for creating new log entries"""
    ip_address: str
    api_accessed: str
    status_code: int
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
