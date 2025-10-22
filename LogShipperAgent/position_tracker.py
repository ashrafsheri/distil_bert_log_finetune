"""
Position Tracker
Tracks file position for log reading and persists it to disk
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional
import logging
from datetime import datetime

class PositionTracker:
    """Tracks and persists file reading position"""
    
    def __init__(self, position_file: str = "position.json"):
        """
        Initialize position tracker
        
        Args:
            position_file: File to store position data
        """
        self.position_file = Path(position_file)
        self.positions: Dict[str, int] = {}
        self.logger = logging.getLogger(__name__)
        
        # Load existing positions
        self._load_positions()
    
    def get_position(self, file_path: str) -> int:
        """
        Get last known position for a file
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Last known byte position
        """
        return self.positions.get(file_path, 0)
    
    def update_position(self, file_path: str, position: int) -> None:
        """
        Update position for a file
        
        Args:
            file_path: Path to the log file
            position: New byte position
        """
        self.positions[file_path] = position
        self._persist_positions()
        self.logger.debug(f"Updated position for {file_path}: {position}")
    
    def reset_position(self, file_path: str) -> None:
        """
        Reset position for a file to 0
        
        Args:
            file_path: Path to the log file
        """
        self.positions[file_path] = 0
        self._persist_positions()
        self.logger.info(f"Reset position for {file_path}")
    
    def get_file_size(self, file_path: str) -> int:
        """
        Get current file size
        
        Args:
            file_path: Path to the file
            
        Returns:
            Current file size in bytes
        """
        try:
            return os.path.getsize(file_path)
        except OSError:
            return 0
    
    def is_file_rotated(self, file_path: str) -> bool:
        """
        Check if file has been rotated (size decreased)
        
        Args:
            file_path: Path to the log file
            
        Returns:
            True if file appears to have been rotated
        """
        current_size = self.get_file_size(file_path)
        last_position = self.get_position(file_path)
        
        # If current size is less than last position, file was likely rotated
        return current_size < last_position
    
    def handle_file_rotation(self, file_path: str) -> None:
        """
        Handle file rotation by resetting position
        
        Args:
            file_path: Path to the log file
        """
        self.logger.info(f"File rotation detected for {file_path}, resetting position")
        self.reset_position(file_path)
    
    def get_stats(self) -> Dict:
        """
        Get position tracking statistics
        
        Returns:
            Dictionary with position stats
        """
        return {
            "tracked_files": len(self.positions),
            "positions": self.positions.copy(),
            "last_updated": datetime.now().isoformat()
        }
    
    def _load_positions(self) -> None:
        """Load positions from file"""
        try:
            if self.position_file.exists():
                with open(self.position_file, 'r') as f:
                    data = json.load(f)
                    self.positions = data.get('positions', {})
                    self.logger.info(f"Loaded positions for {len(self.positions)} files")
            else:
                self.logger.info("No position file found, starting fresh")
        except Exception as e:
            self.logger.error(f"Error loading positions: {e}")
            self.positions = {}
    
    def _persist_positions(self) -> None:
        """Persist positions to file"""
        try:
            data = {
                'positions': self.positions,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.position_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error persisting positions: {e}")
    
    def cleanup_old_positions(self, max_age_days: int = 7) -> int:
        """
        Clean up positions for files that no longer exist
        
        Args:
            max_age_days: Maximum age of position records to keep
            
        Returns:
            Number of positions cleaned up
        """
        cleaned_count = 0
        files_to_remove = []
        
        for file_path in self.positions.keys():
            if not os.path.exists(file_path):
                files_to_remove.append(file_path)
                cleaned_count += 1
        
        for file_path in files_to_remove:
            del self.positions[file_path]
        
        if cleaned_count > 0:
            self._persist_positions()
            self.logger.info(f"Cleaned up {cleaned_count} old position records")
        
        return cleaned_count
