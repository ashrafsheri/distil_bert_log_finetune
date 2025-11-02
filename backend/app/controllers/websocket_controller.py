"""
WebSocket Controller
Handles real-time WebSocket connections for live log updates
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Query, status
from typing import Dict, List, Optional
import json
import uuid
from datetime import datetime

from app.models.log_entry import WebSocketMessage
from app.utils.firebase_auth import verify_firebase_token

router = APIRouter()

# Store active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        """Store WebSocket connection (connection must already be accepted)"""
        print(f"🔌 Storing WebSocket connection for client: {client_id}")
        self.active_connections[client_id] = websocket
        print(f"✅ WebSocket connected. Total active connections: {len(self.active_connections)}")
    
    def disconnect(self, client_id: str):
        """Remove WebSocket connection"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            print(f"🔌 WebSocket disconnected: {client_id}. Total active connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: dict, client_id: str):
        """Send message to specific client"""
        if client_id in self.active_connections:
            try:
                print(f"📤 Sending message to {client_id}: {message}")
                await self.active_connections[client_id].send_text(json.dumps(message))
            except Exception as e:
                print(f"❌ Error sending message to {client_id}: {e}")
                self.disconnect(client_id)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        print(f"📢 Broadcasting message to {len(self.active_connections)} clients: {message}")
        for client_id, connection in self.active_connections.items():
            try:
                print(f"📤 Broadcasting to {client_id}")
                await connection.send_text(json.dumps(message))
            except Exception as e:
                print(f"❌ Error broadcasting to {client_id}: {e}")
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
        print(f"❌ WebSocket connection rejected: Missing authentication token for client {client_id}")
        await websocket.close(code=1008, reason="Authentication token required")
        return
    
    try:
        # Verify Firebase token
        user_info = await verify_firebase_token(token)
        print(f"✅ WebSocket authenticated for user: {user_info.get('uid')}")
    except HTTPException as e:
        print(f"❌ WebSocket connection rejected: Invalid token for client {client_id} - {e.detail}")
        await websocket.close(code=1008, reason=f"Authentication failed: {e.detail}")
        return
    except Exception as e:
        print(f"❌ WebSocket connection error: {e}")
        await websocket.close(code=1011, reason=f"Server error: {str(e)}")
        return
    
    # Connection authenticated successfully, add to manager
    manager.active_connections[client_id] = websocket
    print(f"✅ WebSocket connected. Total active connections: {len(manager.active_connections)}")
    
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            
            # TODO: Handle incoming WebSocket messages
            # This could include:
            # - Client requesting specific log filters
            # - Client subscribing to specific log types
            # - Heartbeat/ping messages
            
            # Placeholder response
            response = {
                "type": "acknowledgment",
                "message": "Message received",
                "timestamp": datetime.now().isoformat()
            }
            
            await manager.send_personal_message(response, client_id)
            
    except WebSocketDisconnect:
        manager.disconnect(client_id)
        print(f"Client {client_id} disconnected")
    except Exception as e:
        print(f"WebSocket error for {client_id}: {e}")
        manager.disconnect(client_id)

# Utility functions for sending log updates
async def send_log_update(log_entry: dict, client_id: str = None):
    """
    Send new log entry to specific client or broadcast to all
    
    Args:
        log_entry: Log entry data
        client_id: Specific client ID (None for broadcast)
    """
    message = {
        "type": "log_update",
        "data": log_entry,
        "timestamp": datetime.now().isoformat()
    }
    print(f"📤 WebSocket message structure: {message}")
    
    if client_id:
        await manager.send_personal_message(message, client_id)
    else:
        await manager.broadcast(message)

async def send_anomaly_alert(alert_data: dict, client_id: str = None):
    """
    Send anomaly detection alert
    
    Args:
        alert_data: Alert information
        client_id: Specific client ID (None for broadcast)
    """
    message = {
        "type": "anomaly_alert",
        "data": alert_data,
        "timestamp": datetime.now().isoformat()
    }
    
    if client_id:
        await manager.send_personal_message(message, client_id)
    else:
        await manager.broadcast(message)
