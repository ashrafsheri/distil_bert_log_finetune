"""
WebSocket Controller
Handles real-time WebSocket connections for live log updates
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Query
from typing import Dict, Optional, NamedTuple
import json
from datetime import datetime
import logging

from app.utils.firebase_auth import verify_firebase_token

logger = logging.getLogger(__name__)

router = APIRouter()

# Connection info to track both websocket and org_id
class ConnectionInfo(NamedTuple):
    websocket: WebSocket
    org_id: Optional[str]
    user_role: Optional[str]

# Store active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, ConnectionInfo] = {}
    
    def connect(self, websocket: WebSocket, client_id: str, org_id: Optional[str] = None, user_role: Optional[str] = None):
        """Store WebSocket connection with org_id (connection must already be accepted)"""
        self.active_connections[client_id] = ConnectionInfo(
            websocket=websocket,
            org_id=org_id,
            user_role=user_role
        )
        logger.info(f"WebSocket connected. Total active connections: {len(self.active_connections)}")
    
    def disconnect(self, client_id: str):
        """Remove WebSocket connection"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info("WebSocket disconnected. Total active connections: %s", len(self.active_connections))
    
    async def send_personal_message(self, message: dict, client_id: str):
        """Send message to specific client"""
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error("Error sending WebSocket message: %s", e)
                self.disconnect(client_id)
    
    async def broadcast(self, message: dict, org_id: Optional[str] = None):
        """Broadcast message to all connected clients, optionally filtered by org_id"""
        # Determine which clients to send to
        target_clients = []
        for client_id, conn_info in self.active_connections.items():
            # If org_id filter is provided, only send to matching orgs or admin users
            if org_id is not None:
                if conn_info.user_role == "admin" or conn_info.org_id == org_id:
                    target_clients.append((client_id, conn_info))
            else:
                # No filter - send to all (fallback for compatibility)
                target_clients.append((client_id, conn_info))
        
        logger.info("Broadcasting message to %s clients", len(target_clients))
        
        for client_id, conn_info in target_clients:
            try:
                await conn_info.websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error("Error broadcasting WebSocket message: %s", e)
                self.disconnect(client_id)

# Global connection manager
manager = ConnectionManager()

@router.websocket("/{client_id}")
async def websocket_endpoint(
    websocket: WebSocket, 
    client_id: str,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for real-time log updates
    
    Requires authentication via Firebase JWT token in query parameter
    
    Args:
        websocket: WebSocket connection
        client_id: Unique client identifier
        token: Firebase JWT token (passed as query parameter since WebSocket doesn't support headers)
    """
    # Accept connection first (required in FastAPI)
    await websocket.accept()
    
    # Verify authentication token
    if not token:
        logger.warning("WebSocket connection rejected: missing authentication token")
        await websocket.close(code=1008, reason="Authentication token required")
        return
    
    try:
        # Verify Firebase token
        user_info = await verify_firebase_token(token)
        logger.info("WebSocket authentication succeeded")
    except HTTPException as e:
        logger.warning("WebSocket connection rejected: invalid token")
        await websocket.close(code=1008, reason=f"Authentication failed: {e.detail}")
        return
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
        await websocket.close(code=1011, reason=f"Server error: {str(e)}")
        return
    
    # Fetch user's org_id and role from database
    user_org_id = None
    user_role = None
    try:
        from app.utils.database import AsyncSessionLocal
        from app.services.user_service import get_user_service
        
        async with AsyncSessionLocal() as db:
            user_service = get_user_service(db)
            db_user = await user_service.get_user(user_info["uid"])
            if db_user:
                user_org_id = db_user.org_id
                user_role = db_user.role
            else:
                logger.warning("WebSocket user not found in database")
    except Exception as e:
        logger.error(f"Error fetching user org_id for WebSocket: {e}")
    
    # Connection authenticated successfully, add to manager with org_id
    manager.connect(
        websocket=websocket,
        client_id=client_id,
        org_id=user_org_id,
        user_role=user_role,
    )
    
    try:
        while True:
            # Keep connection alive and handle incoming messages
            message_text = await websocket.receive_text()
            try:
                payload = json.loads(message_text)
            except json.JSONDecodeError:
                payload = {"type": "message", "raw": message_text}

            message_type = payload.get("type", "message")
            response = {
                "type": "pong" if message_type == "ping" else "acknowledgment",
                "message": "Heartbeat acknowledged" if message_type == "ping" else "Message received",
                "received_type": message_type,
                "timestamp": datetime.now().isoformat(),
            }
            
            await manager.send_personal_message(response, client_id)
            
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error("WebSocket error: %s", e)
        manager.disconnect(client_id)

# Utility functions for sending log updates
async def send_log_update(log_entry: dict, client_id: str = None, org_id: str = None):
    """
    Send new log entry to specific client or broadcast to matching org
    
    Args:
        log_entry: Log entry data
        client_id: Specific client ID (None for broadcast)
        org_id: Organization ID to filter broadcast recipients (None broadcasts to all)
    """
    message = {
        "type": "log_update",
        "data": log_entry,
        "timestamp": datetime.now().isoformat()
    }
    
    if client_id:
        await manager.send_personal_message(message, client_id)
    else:
        # Broadcast to clients matching the org_id
        await manager.broadcast(message, org_id=org_id)

async def send_anomaly_alert(alert_data: dict, client_id: str = None, org_id: str = None):
    """
    Send anomaly detection alert
    
    Args:
        alert_data: Alert information
        client_id: Specific client ID (None for broadcast)
        org_id: Organization ID to filter broadcast recipients (None broadcasts to all)
    """
    message = {
        "type": "anomaly_alert",
        "data": alert_data,
        "timestamp": datetime.now().isoformat()
    }
    
    if client_id:
        await manager.send_personal_message(message, client_id)
    else:
        await manager.broadcast(message, org_id=org_id)
