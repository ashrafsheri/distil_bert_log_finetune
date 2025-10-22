"""
Sliding Window Implementation
Manages log batches with acknowledgment tracking and retry logic
"""

import time
import asyncio
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import json

@dataclass
class PendingBatch:
    """Represents a batch of logs waiting for acknowledgment"""
    batch_id: str
    raw_logs: List[str]
    timestamp: datetime
    retry_count: int = 0
    max_retries: int = 3
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API transmission"""
        return {
            "batch_id": self.batch_id,
            "raw_logs": self.raw_logs
        }

class SlidingWindow:
    """Sliding window for managing log batches with acknowledgments"""
    
    def __init__(self, window_size: int = 1000, ack_timeout: int = 30):
        """
        Initialize sliding window
        
        Args:
            window_size: Maximum number of pending batches
            ack_timeout: Timeout for acknowledgments in seconds
        """
        self.window_size = window_size
        self.ack_timeout = ack_timeout
        self.pending_batches: Dict[str, PendingBatch] = {}
        self.acknowledged_batches: Set[str] = set()
        self.logger = logging.getLogger(__name__)
        self._batch_counter = 0
        
    def add_batch(self, raw_logs: List[str], max_retries: int = 3) -> str:
        """
        Add a new batch to the sliding window
        
        Args:
            raw_logs: List of raw log lines
            max_retries: Maximum retry attempts
            
        Returns:
            Batch ID for tracking
        """
        if not raw_logs:
            return None
            
        # Generate unique batch ID
        batch_id = f"batch_{int(time.time())}_{self._batch_counter}"
        self._batch_counter += 1
        
        # Create pending batch
        batch = PendingBatch(
            batch_id=batch_id,
            raw_logs=raw_logs,
            timestamp=datetime.now(),
            max_retries=max_retries
        )
        
        # Add to pending batches
        self.pending_batches[batch_id] = batch
        
        # Check if window is full
        if len(self.pending_batches) > self.window_size:
            self._remove_oldest_batch()
            
        self.logger.info(f"Added batch {batch_id} with {len(raw_logs)} logs")
        return batch_id
    
    def acknowledge_batch(self, batch_id: str) -> bool:
        """
        Mark a batch as acknowledged
        
        Args:
            batch_id: ID of the batch to acknowledge
            
        Returns:
            True if batch was found and acknowledged
        """
        if batch_id in self.pending_batches:
            # Move from pending to acknowledged
            del self.pending_batches[batch_id]
            self.acknowledged_batches.add(batch_id)
            self.logger.info(f"Batch {batch_id} acknowledged")
            return True
        return False
    
    def get_pending_batches(self) -> List[PendingBatch]:
        """
        Get all pending batches that need to be sent
        
        Returns:
            List of pending batches
        """
        return list(self.pending_batches.values())
    
    def get_timed_out_batches(self) -> List[PendingBatch]:
        """
        Get batches that have timed out and need retry
        
        Returns:
            List of timed out batches
        """
        now = datetime.now()
        timed_out = []
        
        for batch in self.pending_batches.values():
            if (now - batch.timestamp).seconds > self.ack_timeout:
                timed_out.append(batch)
                
        return timed_out
    
    def retry_batch(self, batch_id: str) -> bool:
        """
        Mark a batch for retry
        
        Args:
            batch_id: ID of the batch to retry
            
        Returns:
            True if batch was found and marked for retry
        """
        if batch_id in self.pending_batches:
            batch = self.pending_batches[batch_id]
            batch.retry_count += 1
            batch.timestamp = datetime.now()  # Reset timeout
            
            if batch.retry_count > batch.max_retries:
                # Remove batch if max retries exceeded
                del self.pending_batches[batch_id]
                self.logger.warning(f"Batch {batch_id} exceeded max retries, removing")
                return False
            else:
                self.logger.info(f"Batch {batch_id} marked for retry ({batch.retry_count}/{batch.max_retries})")
                return True
        return False
    
    def _remove_oldest_batch(self):
        """Remove the oldest batch from the window"""
        if not self.pending_batches:
            return
            
        # Find oldest batch
        oldest_batch_id = min(
            self.pending_batches.keys(),
            key=lambda x: self.pending_batches[x].timestamp
        )
        
        # Remove it
        del self.pending_batches[oldest_batch_id]
        self.logger.warning(f"Removed oldest batch {oldest_batch_id} due to window size limit")
    
    def get_stats(self) -> Dict:
        """
        Get window statistics
        
        Returns:
            Dictionary with window statistics
        """
        return {
            "pending_batches": len(self.pending_batches),
            "acknowledged_batches": len(self.acknowledged_batches),
            "window_size": self.window_size,
            "ack_timeout": self.ack_timeout,
            "oldest_pending": min(
                (batch.timestamp for batch in self.pending_batches.values()),
                default=None
            ),
            "newest_pending": max(
                (batch.timestamp for batch in self.pending_batches.values()),
                default=None
            )
        }
    
    def cleanup_old_acknowledgments(self, max_age_hours: int = 24):
        """
        Clean up old acknowledged batches to prevent memory leaks
        
        Args:
            max_age_hours: Maximum age of acknowledged batches to keep
        """
        # This is a placeholder - in a real implementation, you might want to
        # store acknowledged batches with timestamps and clean them up
        # For now, we'll just clear the set periodically
        if len(self.acknowledged_batches) > 1000:
            self.acknowledged_batches.clear()
            self.logger.info("Cleaned up old acknowledgments")
    
    def is_batch_acknowledged(self, batch_id: str) -> bool:
        """
        Check if a batch has been acknowledged
        
        Args:
            batch_id: ID of the batch to check
            
        Returns:
            True if batch is acknowledged
        """
        return batch_id in self.acknowledged_batches
    
    def get_retry_batches(self) -> List[PendingBatch]:
        """
        Get batches that need to be retried
        
        Returns:
            List of batches that need retry
        """
        retry_batches = []
        now = datetime.now()
        
        for batch in self.pending_batches.values():
            # Check if batch has timed out
            if (now - batch.timestamp).seconds > self.ack_timeout:
                # Check if we can retry
                if batch.retry_count < batch.max_retries:
                    retry_batches.append(batch)
                else:
                    # Remove batch that exceeded max retries
                    del self.pending_batches[batch.batch_id]
                    self.logger.warning(f"Removed batch {batch.batch_id} - exceeded max retries")
        
        return retry_batches
