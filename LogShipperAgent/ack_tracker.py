"""
Acknowledgment Tracking System
Tracks and manages acknowledgments for sent log batches
"""

import json
import time
from typing import Dict, Set, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging
import threading
from pathlib import Path

@dataclass
class AcknowledgmentRecord:
    """Record of an acknowledgment"""
    batch_id: str
    timestamp: datetime
    response_time: float
    success: bool
    error_message: Optional[str] = None

class AcknowledgmentTracker:
    """Tracks acknowledgments and manages retry logic"""
    
    def __init__(self, persistence_file: str = "ack_tracker.json"):
        """
        Initialize acknowledgment tracker
        
        Args:
            persistence_file: File to persist acknowledgment data
        """
        self.persistence_file = Path(persistence_file)
        self.acknowledgments: Dict[str, AcknowledgmentRecord] = {}
        self.pending_acks: Set[str] = set()
        self.failed_acks: Set[str] = set()
        self.logger = logging.getLogger(__name__)
        self._lock = threading.Lock()
        
        # Load existing data
        self._load_persisted_data()
    
    def mark_pending(self, batch_id: str) -> None:
        """
        Mark a batch as pending acknowledgment
        
        Args:
            batch_id: ID of the batch to mark as pending
        """
        with self._lock:
            self.pending_acks.add(batch_id)
            self.logger.debug(f"Marked batch {batch_id} as pending acknowledgment")
    
    def record_acknowledgment(self, batch_id: str, success: bool, 
                            response_time: float, error_message: Optional[str] = None) -> None:
        """
        Record an acknowledgment response
        
        Args:
            batch_id: ID of the batch
            success: Whether the acknowledgment was successful
            response_time: Time taken to receive response
            error_message: Error message if unsuccessful
        """
        with self._lock:
            # Remove from pending
            self.pending_acks.discard(batch_id)
            
            # Create acknowledgment record
            ack_record = AcknowledgmentRecord(
                batch_id=batch_id,
                timestamp=datetime.now(),
                response_time=response_time,
                success=success,
                error_message=error_message
            )
            
            # Store the record
            self.acknowledgments[batch_id] = ack_record
            
            if success:
                self.logger.info(f"Batch {batch_id} acknowledged successfully in {response_time:.2f}s")
            else:
                self.failed_acks.add(batch_id)
                self.logger.error(f"Batch {batch_id} acknowledgment failed: {error_message}")
            
            # Persist data
            self._persist_data()
    
    def is_pending(self, batch_id: str) -> bool:
        """
        Check if a batch is pending acknowledgment
        
        Args:
            batch_id: ID of the batch to check
            
        Returns:
            True if batch is pending
        """
        with self._lock:
            return batch_id in self.pending_acks
    
    def is_acknowledged(self, batch_id: str) -> bool:
        """
        Check if a batch has been acknowledged
        
        Args:
            batch_id: ID of the batch to check
            
        Returns:
            True if batch is acknowledged
        """
        with self._lock:
            return batch_id in self.acknowledgments and self.acknowledgments[batch_id].success
    
    def get_pending_batches(self) -> List[str]:
        """
        Get list of pending batch IDs
        
        Returns:
            List of pending batch IDs
        """
        with self._lock:
            return list(self.pending_acks)
    
    def get_failed_batches(self) -> List[str]:
        """
        Get list of failed batch IDs
        
        Returns:
            List of failed batch IDs
        """
        with self._lock:
            return list(self.failed_acks)
    
    def get_acknowledgment_stats(self) -> Dict:
        """
        Get acknowledgment statistics
        
        Returns:
            Dictionary with acknowledgment statistics
        """
        with self._lock:
            total_acks = len(self.acknowledgments)
            successful_acks = sum(1 for ack in self.acknowledgments.values() if ack.success)
            failed_acks = total_acks - successful_acks
            pending_acks = len(self.pending_acks)
            
            # Calculate average response time
            if successful_acks > 0:
                avg_response_time = sum(
                    ack.response_time for ack in self.acknowledgments.values() 
                    if ack.success
                ) / successful_acks
            else:
                avg_response_time = 0.0
            
            return {
                "total_acknowledgments": total_acks,
                "successful_acknowledgments": successful_acks,
                "failed_acknowledgments": failed_acks,
                "pending_acknowledgments": pending_acks,
                "success_rate": successful_acks / total_acks if total_acks > 0 else 0.0,
                "average_response_time": avg_response_time,
                "oldest_pending": min(
                    (ack.timestamp for ack in self.acknowledgments.values() 
                     if ack.batch_id in self.pending_acks),
                    default=None
                )
            }
    
    def get_acknowledgment_history(self, limit: int = 100) -> List[Dict]:
        """
        Get acknowledgment history
        
        Args:
            limit: Maximum number of records to return
            
        Returns:
            List of acknowledgment records
        """
        with self._lock:
            # Sort by timestamp (newest first)
            sorted_acks = sorted(
                self.acknowledgments.values(),
                key=lambda x: x.timestamp,
                reverse=True
            )
            
            # Convert to dictionaries and limit results
            return [
                {
                    "batch_id": ack.batch_id,
                    "timestamp": ack.timestamp.isoformat(),
                    "response_time": ack.response_time,
                    "success": ack.success,
                    "error_message": ack.error_message
                }
                for ack in sorted_acks[:limit]
            ]
    
    def cleanup_old_records(self, max_age_hours: int = 24) -> int:
        """
        Clean up old acknowledgment records
        
        Args:
            max_age_hours: Maximum age of records to keep
            
        Returns:
            Number of records cleaned up
        """
        with self._lock:
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            old_records = [
                batch_id for batch_id, ack in self.acknowledgments.items()
                if ack.timestamp < cutoff_time
            ]
            
            for batch_id in old_records:
                del self.acknowledgments[batch_id]
                self.pending_acks.discard(batch_id)
                self.failed_acks.discard(batch_id)
            
            if old_records:
                self.logger.info(f"Cleaned up {len(old_records)} old acknowledgment records")
                self._persist_data()
            
            return len(old_records)
    
    def reset_failed_batches(self) -> List[str]:
        """
        Reset failed batches to allow retry
        
        Returns:
            List of reset batch IDs
        """
        with self._lock:
            reset_batches = list(self.failed_acks)
            self.failed_acks.clear()
            self.logger.info(f"Reset {len(reset_batches)} failed batches for retry")
            return reset_batches
    
    def _load_persisted_data(self) -> None:
        """Load acknowledgment data from persistence file"""
        try:
            if self.persistence_file.exists():
                with open(self.persistence_file, 'r') as f:
                    data = json.load(f)
                
                # Load acknowledgments
                for batch_id, ack_data in data.get('acknowledgments', {}).items():
                    self.acknowledgments[batch_id] = AcknowledgmentRecord(
                        batch_id=ack_data['batch_id'],
                        timestamp=datetime.fromisoformat(ack_data['timestamp']),
                        response_time=ack_data['response_time'],
                        success=ack_data['success'],
                        error_message=ack_data.get('error_message')
                    )
                
                # Load pending and failed sets
                self.pending_acks = set(data.get('pending_acks', []))
                self.failed_acks = set(data.get('failed_acks', []))
                
                self.logger.info(f"Loaded {len(self.acknowledgments)} acknowledgment records")
                
        except Exception as e:
            self.logger.error(f"Error loading persisted data: {e}")
    
    def _persist_data(self) -> None:
        """Persist acknowledgment data to file"""
        try:
            data = {
                'acknowledgments': {
                    batch_id: {
                        'batch_id': ack.batch_id,
                        'timestamp': ack.timestamp.isoformat(),
                        'response_time': ack.response_time,
                        'success': ack.success,
                        'error_message': ack.error_message
                    }
                    for batch_id, ack in self.acknowledgments.items()
                },
                'pending_acks': list(self.pending_acks),
                'failed_acks': list(self.failed_acks)
            }
            
            with open(self.persistence_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error persisting data: {e}")
    
    def get_health_status(self) -> Dict:
        """
        Get health status of the acknowledgment system
        
        Returns:
            Dictionary with health status
        """
        with self._lock:
            stats = self.get_acknowledgment_stats()
            
            # Determine health status
            if stats['success_rate'] >= 0.95:
                health_status = "healthy"
            elif stats['success_rate'] >= 0.80:
                health_status = "warning"
            else:
                health_status = "critical"
            
            return {
                "status": health_status,
                "stats": stats,
                "pending_count": len(self.pending_acks),
                "failed_count": len(self.failed_acks),
                "last_cleanup": datetime.now().isoformat()
            }
