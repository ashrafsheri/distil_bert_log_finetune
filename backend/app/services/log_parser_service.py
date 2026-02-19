"""
Log Parser Service
Parses Apache log entries and extracts structured data
"""

import re
from datetime import datetime
from typing import Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class LogParserService:
    """
    Log Parser Service
    Parses Apache log entries and extracts structured data
    """
    
    def __init__(self):
        """
        Initialize LogParserService
        
        Returns:
            None
        """
        # Only regex for timestamp parsing
        self.timestamp_pattern = re.compile(r'\[([^\]]+)\]')
    
    def parse_apache_log(self, log_line: str) -> Optional[Dict]:
        """
        Parse Apache log line using string splitting for reliable extraction
        
        Args:
            log_line: Raw Apache log line
            
        Returns:
            Dict with parsed log data or None if parsing fails
        """
        try:
            logger.debug(f"Parsing log line: {log_line[:200]}...")
            # Clean the log line
            log_line = log_line.strip()
            logger.debug(f"Cleaned log line: {log_line[:200]}...")
            # Extract timestamp using regex (only part that needs regex)
            timestamp_match = self.timestamp_pattern.search(log_line)
            if not timestamp_match:
                logger.warning(f"No timestamp found in log: {log_line[:100]}...")
                return None
            
            timestamp_str = timestamp_match.group(1)
            
            # Split the log line by spaces
            parts = log_line.split()
            
            if len(parts) < 8:
                logger.warning(f"Not enough parts in log line: {len(parts)} parts")
                return None
            
            # Extract basic fields
            ip_address = parts[0]
            
            # Find the request part (starts with " and ends with ")
            request_start = log_line.find('\"')
            if request_start == -1:
                logger.warning(f"No request start found in log: {log_line[:100]}...")
                return None
            
            # Find the end of the request (next " after the start)
            request_end = log_line.find('\"', request_start + 1)
            if request_end == -1:
                logger.warning(f"No request end found in log: {log_line[:100]}...")
                return None
            
            request_line = log_line[request_start + 1:request_end]
            request_parts = request_line.split()
            logger.debug(f"Request parts: {request_parts}")
            if len(request_parts) < 2:
                logger.warning(f"Invalid request format: {request_line}")
                return None
            
            method = request_parts[0]
            
            # Handle path and protocol
            if len(request_parts) == 2:
                # No protocol specified
                path = request_parts[1]
                protocol = "HTTP/1.1"  # Default
            else:
                # Protocol specified
                path = request_parts[1]
                protocol = request_parts[2]
            
            # Find the position after the request quote to get remaining parts
            after_request = request_end + 1
            remaining = log_line[after_request:].strip()
            remaining_parts = remaining.split()
            
            # Check if it's combined log format by looking for quoted fields
            # Combined format has status, size, then quoted referer and user agent
            is_combined = len(remaining_parts) >= 4 and any(part.startswith('\"') for part in remaining_parts[2:])
            
            # Extract status code and size based on format
            try:
                if is_combined:
                    # Combined format: status and size are before the quoted referer and user agent
                    status_code = int(remaining_parts[0].strip('"'))
                    size = int(remaining_parts[1].strip('"')) if remaining_parts[1].strip('"') != '-' else 0
                else:
                    # Common format: status and size are the last two parts
                    status_code = int(parts[-2])
                    size = int(parts[-1]) if parts[-1] != '-' else 0
            except (ValueError, IndexError):
                logger.warning(f"Could not parse status code or size from: {remaining_parts[:4] if is_combined else parts[-2:]}")
                return None
            
            if is_combined:
                # Combined log format - extract referer and user agent
                try:
                    # Find referer (first quoted string after request)
                    referer_start = remaining.find('"')
                    referer_end = remaining.find('"', referer_start + 1)
                    referer = remaining[referer_start + 1:referer_end] if referer_start != -1 and referer_end != -1 else ""
                    
                    # Find user agent (second quoted string)
                    user_agent_start = remaining.find('"', referer_end + 1)
                    user_agent_end = remaining.find('"', user_agent_start + 1)
                    user_agent = remaining[user_agent_start + 1:user_agent_end] if user_agent_start != -1 and user_agent_end != -1 else ""
                except:
                    referer = ""
                    user_agent = ""
                logger.debug(
                    "Parsed combined log -> ip=%s method=%s path=%s status=%s size=%s referer=%s ua=%s",
                    ip_address,
                    method,
                    path,
                    status_code,
                    size,
                    referer,
                    user_agent
                )
                return {
                    "ip_address": ip_address,
                    "timestamp": self._parse_timestamp(timestamp_str),
                    "method": method,
                    "path": path,
                    "protocol": protocol,
                    "status_code": status_code,
                    "size": size,
                    "referer": referer,
                    "user_agent": user_agent,
                    "raw_log": log_line
                }
            else:
                # Common log format
                return {
                    "ip_address": ip_address,
                    "timestamp": self._parse_timestamp(timestamp_str),
                    "method": method,
                    "path": path,
                    "protocol": protocol,
                    "status_code": status_code,
                    "size": size,
                    "raw_log": log_line
                }
            
        except Exception as e:
            logger.error(f"Error parsing log line: {e}")
            return None
    
    
    def parse_nginx_log(self, log_line: str) -> Optional[Dict]:
        """
        Parse Nginx log line (supports both access log format and combined format)
        
        Args:
            log_line: Raw Nginx log line
            
        Returns:
            Dict with parsed log data or None if parsing fails
        """
        try:
            logger.debug(f"Parsing nginx log line: {log_line[:200]}...")
            log_line = log_line.strip()
            
            # Nginx combined log format:
            # $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
            # Example: 192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
            
            # Extract timestamp using regex
            timestamp_match = self.timestamp_pattern.search(log_line)
            if not timestamp_match:
                logger.warning(f"No timestamp found in nginx log: {log_line[:100]}...")
                return None
            
            timestamp_str = timestamp_match.group(1)
            
            # Split the log line by spaces
            parts = log_line.split()
            
            if len(parts) < 8:
                logger.warning(f"Not enough parts in nginx log line: {len(parts)} parts")
                return None
            
            # Extract IP address
            ip_address = parts[0]
            
            # Find the request part (starts with " and ends with ")
            request_start = log_line.find('\"')
            if request_start == -1:
                logger.warning(f"No request start found in nginx log: {log_line[:100]}...")
                return None
            
            request_end = log_line.find('\"', request_start + 1)
            if request_end == -1:
                logger.warning(f"No request end found in nginx log: {log_line[:100]}...")
                return None
            
            request_line = log_line[request_start + 1:request_end]
            request_parts = request_line.split()
            
            if len(request_parts) < 2:
                logger.warning(f"Invalid request format in nginx log: {request_line}")
                return None
            
            method = request_parts[0]
            path = request_parts[1]
            protocol = request_parts[2] if len(request_parts) > 2 else "HTTP/1.1"
            
            # Get remaining parts after the request
            after_request = request_end + 1
            remaining = log_line[after_request:].strip()
            remaining_parts = remaining.split()
            
            # Extract status code and size
            try:
                status_code = int(remaining_parts[0])
                size = int(remaining_parts[1]) if remaining_parts[1] != '-' else 0
            except (ValueError, IndexError):
                logger.warning(f"Could not parse status code or size from nginx log: {remaining_parts[:2]}")
                return None
            
            # Extract referer and user agent if present (combined format)
            referer = ""
            user_agent = ""
            
            if len(remaining_parts) > 2:
                try:
                    # Find referer (first quoted string after status and size)
                    referer_start = remaining.find('\"')
                    referer_end = remaining.find('\"', referer_start + 1)
                    referer = remaining[referer_start + 1:referer_end] if referer_start != -1 and referer_end != -1 else ""
                    
                    # Find user agent (second quoted string)
                    user_agent_start = remaining.find('\"', referer_end + 1)
                    user_agent_end = remaining.find('\"', user_agent_start + 1)
                    user_agent = remaining[user_agent_start + 1:user_agent_end] if user_agent_start != -1 and user_agent_end != -1 else ""
                except Exception as e:
                    logger.debug(f"Could not extract referer/user_agent from nginx log: {e}")
            
            logger.debug(
                "Parsed nginx log -> ip=%s method=%s path=%s status=%s size=%s",
                ip_address,
                method,
                path,
                status_code,
                size
            )
            
            return {
                "ip_address": ip_address,
                "timestamp": self._parse_timestamp(timestamp_str),
                "method": method,
                "path": path,
                "protocol": protocol,
                "status_code": status_code,
                "size": size,
                "referer": referer,
                "user_agent": user_agent,
                "raw_log": log_line
            }
            
        except Exception as e:
            logger.error(f"Error parsing nginx log line: {e}")
            return None
    
    
    def _parse_timestamp(self, timestamp_str: str) -> str:
        """
        Parse Apache timestamp format to ISO format
        
        Args:
            timestamp_str: Apache timestamp like "22/Oct/2025:10:30:48 +0000"
            
        Returns:
            ISO formatted timestamp string
        """
        try:
            # Try standard Apache format first: "22/Oct/2025:10:30:48 +0000"
            dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            return dt.isoformat()
        except ValueError:
            try:
                # Try alternative format: "03:14 23 Oct 2025"
                dt = datetime.strptime(timestamp_str, "%H:%M %d %b %Y")
                return dt.isoformat()
            except ValueError:
                try:
                    # Try another format: "23/Oct/2025:03:14:31 +0500"
                    dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
                    return dt.isoformat()
                except ValueError:
                    # If all parsing fails, return current timestamp
                    logger.warning(f"Could not parse timestamp: {timestamp_str}")
                    return datetime.utcnow().isoformat()
    
    def format_for_frontend(self, parsed_log: Dict, anomaly_result: Dict) -> Dict:
        """
        Format parsed log data for frontend consumption
        
        Args:
            parsed_log: Parsed log data from Apache log
            anomaly_result: Anomaly detection result
            
        Returns:
            Formatted log entry for frontend
        """
        try:
            # Format timestamp for display
            timestamp_dt = datetime.fromisoformat(parsed_log["timestamp"].replace("Z", "+00:00"))
            formatted_timestamp = timestamp_dt.strftime("%H:%M %d %b %Y")
            
            return {
                "timestamp": formatted_timestamp,
                "ip_address": parsed_log["ip_address"],
                "api_accessed": parsed_log["path"],
                "status_code": parsed_log["status_code"],
                "infected": anomaly_result.get("is_anomaly", False),
                "anomaly_score": anomaly_result.get("anomaly_score", 0.0),
                "anomaly_details": anomaly_result.get("details", {}),
                "raw_log": parsed_log["raw_log"],
                "method": parsed_log.get("method", ""),
                "protocol": parsed_log.get("protocol", ""),
                "size": parsed_log.get("size", 0),
                "referer": parsed_log.get("referer", ""),
                "user_agent": parsed_log.get("user_agent", "")
            }
            
        except Exception as e:
            logger.error(f"Error formatting log for frontend: {e}")
            # Return basic format if formatting fails
            return {
                "timestamp": parsed_log.get("timestamp", ""),
                "ip_address": parsed_log.get("ip_address", ""),
                "api_accessed": parsed_log.get("path", ""),
                "status_code": parsed_log.get("status_code", 0),
                "infected": anomaly_result.get("is_anomaly", False),
                "anomaly_score": anomaly_result.get("anomaly_score", 0.0),
                "anomaly_details": anomaly_result.get("details", {}),
                "raw_log": parsed_log.get("raw_log", "")
            }
