"""
Anomaly Detection Service
Communicates with the realtime anomaly detection microservice
"""

import httpx
from typing import List, Dict, Optional
import logging
import asyncio

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
    
    
