"""
Raw Log Reader
Reads raw log lines from files without parsing
"""

import os
from typing import List, Tuple, Optional
import logging
from pathlib import Path

class RawLogReader:
    """Reads raw log lines from files"""
    
    def __init__(self):
        """Initialize raw log reader"""
        self.logger = logging.getLogger(__name__)
    
    def read_logs(self, file_path: str, start_position: int = 0, max_lines: int = 1000) -> Tuple[List[str], int]:
        """
        Read raw log lines from file
        
        Args:
            file_path: Path to log file
            start_position: Byte position to start reading from
            max_lines: Maximum number of lines to read
            
        Returns:
            Tuple of (raw_log_lines, new_position)
        """
        raw_logs = []
        new_position = start_position
        
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"Log file not found: {file_path}")
                return raw_logs, new_position
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(start_position)
                
                lines_read = 0
                for line in f:
                    if lines_read >= max_lines:
                        break
                        
                    line = line.strip()
                    if line and not line.startswith('#'):
                        raw_logs.append(line)
                        lines_read += 1
                    
                    new_position = f.tell()
                    
        except FileNotFoundError:
            self.logger.error(f"Log file not found: {file_path}")
        except PermissionError:
            self.logger.error(f"Permission denied reading file: {file_path}")
        except Exception as e:
            self.logger.error(f"Error reading log file {file_path}: {e}")
            
        return raw_logs, new_position
    
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
    
    def is_file_rotated(self, file_path: str, last_position: int) -> bool:
        """
        Check if file has been rotated (size decreased)
        
        Args:
            file_path: Path to the log file
            last_position: Last known position
            
        Returns:
            True if file appears to have been rotated
        """
        current_size = self.get_file_size(file_path)
        return current_size < last_position
    
    def read_new_logs(self, file_path: str, last_position: int, max_lines: int = 1000) -> Tuple[List[str], int, bool]:
        """
        Read new log lines since last position
        
        Args:
            file_path: Path to log file
            last_position: Last known position
            max_lines: Maximum number of lines to read
            
        Returns:
            Tuple of (raw_log_lines, new_position, was_rotated)
        """
        # Check if file was rotated
        was_rotated = self.is_file_rotated(file_path, last_position)
        
        if was_rotated:
            self.logger.info(f"File rotation detected for {file_path}, reading from beginning")
            start_position = 0
        else:
            start_position = last_position
        
        raw_logs, new_position = self.read_logs(file_path, start_position, max_lines)
        
        return raw_logs, new_position, was_rotated
