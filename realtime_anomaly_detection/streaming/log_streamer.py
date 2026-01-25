"""
Real-time Log Streaming Simulator
Streams logs from a file and displays anomaly detection results in real-time
with color-coded output (RED for anomalies, GREEN for normal)
"""

import time
import sys
import argparse
from pathlib import Path
from typing import Optional
import requests
from datetime import datetime
import logging

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

logger = logging.getLogger(__name__)

class LogStreamer:
    """Stream logs and display real-time anomaly detection"""
    
    def __init__(self, api_url: str = "http://localhost:8000", delay: float = 0.1):
        self.api_url = api_url
        self.delay = delay
        self.stats = {
            'total_logs': 0,
            'anomalies': 0,
            'normal': 0,
            'errors': 0
        }
    
    def check_health(self) -> bool:
        """Check if API is healthy"""
        try:
            response = requests.get(f"{self.api_url}/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                logger.info("API is healthy")
                
                # Handle both static and adaptive server responses
                if 'phase' in data:
                    # Adaptive server
                    logger.info(f"Mode: ADAPTIVE")
                    logger.info(f"Phase: {data.get('phase', 'unknown')}")
                    logger.info(f"Logs processed: {data.get('logs_processed', 0):,}")
                    logger.info(f"Active models: {data.get('active_models', '?')}")
                    if data.get('transformer_ready', False):
                        logger.info("Transformer trained and ready")
                    else:
                        logger.info("Transformer training pending")
                else:
                    # Static server
                    logger.info("Mode: STATIC")
                    logger.info(f"Vocabulary size: {data.get('vocab_size', 0):,}")
                    logger.info(f"Threshold: {data.get('threshold', 0.0):.4f}")
                return True
            else:
                logger.error(f"API unhealthy: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Cannot connect to API: {e}")
            return False
    
    def detect_anomaly(self, log_line: str, session_id: Optional[str] = None) -> dict:
        """Send log to API for detection"""
        try:
            response = requests.post(
                f"{self.api_url}/detect",
                json={"log_line": log_line, "session_id": session_id},
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                # Return error info for debugging
                return {
                    'error': True,
                    'status_code': response.status_code,
                    'detail': response.text[:200] if hasattr(response, 'text') else 'Unknown error'
                }
                
        except requests.Timeout:
            return {'error': True, 'detail': 'Request timeout'}
        except requests.ConnectionError:
            return {'error': True, 'detail': 'Connection failed'}
        except Exception as e:
            return {'error': True, 'detail': str(e)[:200]}
    
    def print_detection_result(self, log_line: str, result: dict):
        """Print detection result with colors"""
        if result is None:
            logger.error(f"[ERROR] {log_line[:100]}")
            self.stats['errors'] += 1
            return
        
        # Check for API errors
        if result.get('error', False):
            # Only print error details occasionally (every 100th error) to avoid spam
            self.stats['errors'] += 1
            if self.stats['errors'] % 100 == 1:
                logger.error(f"API Error: {result.get('detail', 'Unknown')}")
                logger.error(f"Log: {log_line[:80]}")
            return
        
        is_anomaly = result['is_anomaly']
        score = result['anomaly_score']
        
        # Color based on anomaly status
        if is_anomaly:
            color = Colors.RED
            status = "ANOMALY"
            self.stats['anomalies'] += 1
        else:
            color = Colors.GREEN
            status = "NORMAL "
            self.stats['normal'] += 1
        
        self.stats['total_logs'] += 1
        
        # Get detection details
        details = result.get('details', {})
        rule = details.get('rule_based', {})
        iso = details.get('isolation_forest', {})
        trans = details.get('transformer', {})
        
        # Get adaptive learning status
        phase = result.get('phase', 'unknown')
        logs_processed = details.get('logs_processed', 0)
        transformer_ready = details.get('transformer_ready', False)
        
        # Format output
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Phase indicator
        if phase == 'warmup':
            phase_str = f"[WARMUP:{logs_processed}]"
        elif phase == 'training':
            phase_str = "[TRAINING...]"
        elif phase == 'ensemble':
            phase_str = "[FULL-3M]"
        else:
            phase_str = ""
        
        status_line = f"[{status}] {phase_str} [{timestamp}] Score: {score:.3f}"
        
        # Show which detectors triggered
        detectors = []
        if rule.get('is_attack'):
            detectors.append(f"R:{','.join(rule.get('attack_types', []))[:20]}")
        if iso.get('is_anomaly'):
            detectors.append(f"I:{iso.get('score', 0):.2f}")
        if trans.get('is_anomaly'):
            detectors.append(f"T:{trans.get('score', 0):.2f}")
        elif transformer_ready and trans.get('score', 0) > 0:
            # Show transformer score even if not anomaly
            detectors.append(f"T:{trans.get('score', 0):.2f}")
        
        if detectors:
            status_line += f" [{' | '.join(detectors)}]"
        
        # Print log excerpt
        log_data = details.get('log_data', {})
        path = log_data.get('path', '')
        method = log_data.get('method', '')
        status_code = log_data.get('status', '')
        
        log_line = f"{method} {path[:60]} {status_code}"
        
        if is_anomaly:
            logger.warning(f"{status_line} {log_line}")
        else:
            logger.info(f"{status_line} {log_line}")
    
    def print_stats(self):
        """Print statistics"""
        total = self.stats['total_logs']
        anomalies = self.stats['anomalies']
        normal = self.stats['normal']
        errors = self.stats['errors']
        
        if total == 0:
            return
        
        anomaly_rate = (anomalies / total * 100) if total > 0 else 0
        
        logger.info("="*80)
        logger.info("STREAMING STATISTICS")
        logger.info("="*80)
        logger.info(f"Total logs processed: {total:,}")
        logger.info(f"Normal logs: {normal:,} ({normal/total*100:.1f}%)")
        logger.info(f"Anomalies detected: {anomalies:,} ({anomaly_rate:.1f}%)")
        if errors > 0:
            logger.info(f"Errors: {errors:,}")
        logger.info("="*80)
    
    def stream_file(self, log_file: Path, session_id: Optional[str] = None, 
                    max_logs: Optional[int] = None):
        """Stream logs from file with real-time detection"""
        if not log_file.exists():
            logger.error(f"Log file not found: {log_file}")
            return
        
        logger.info("="*80)
        logger.info("REAL-TIME LOG ANOMALY DETECTION")
        logger.info("="*80)
        logger.info(f"Log file: {log_file}")
        logger.info(f"API: {self.api_url}")
        logger.info(f"Delay: {self.delay}s between logs")
        if session_id:
            logger.info(f"Session ID: {session_id}")
        logger.info("="*80)
        
        logger.info("Legend:")
        logger.info("[ANOMALY] - Detected attack/anomaly")
        logger.info("[NORMAL]  - Normal traffic")
        logger.info("[R:type] - Rule-based detection")
        logger.info("[I:score] - Isolation Forest score")
        logger.info("[T:score] - Transformer score")
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Detect anomaly
                    result = self.detect_anomaly(line, session_id)
                    self.print_detection_result(line, result)
                    
                    # Delay to simulate real-time streaming
                    time.sleep(self.delay)
                    
                    # Stop if max_logs reached
                    if max_logs and i >= max_logs:
                        break
                    
                    # Print stats every 100 logs
                    if i % 100 == 0:
                        self.print_stats()
        
        except KeyboardInterrupt:
            logger.info("Streaming interrupted by user")
        except Exception as e:
            logger.error(f"Error during streaming: {e}")
        finally:
            self.print_stats()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Real-time Log Streaming Simulator with Anomaly Detection"
    )
    parser.add_argument(
        '--log-file', '-f',
        type=str,
        required=True,
        help='Path to log file to stream'
    )
    parser.add_argument(
        '--api-url', '-u',
        type=str,
        default='http://localhost:8000',
        help='API URL (default: http://localhost:8000)'
    )
    parser.add_argument(
        '--delay', '-d',
        type=float,
        default=0.1,
        help='Delay between logs in seconds (default: 0.1)'
    )
    parser.add_argument(
        '--session-id', '-s',
        type=str,
        default=None,
        help='Session ID for grouping logs (default: use IP from log)'
    )
    parser.add_argument(
        '--max-logs', '-n',
        type=int,
        default=None,
        help='Maximum number of logs to stream (default: all)'
    )
    
    args = parser.parse_args()
    
    # Initialize streamer
    streamer = LogStreamer(api_url=args.api_url, delay=args.delay)
    
    # Check API health
    if not streamer.check_health():
        logger.error("API is not available. Please start the server first:")
        logger.error("cd realtime_anomaly_detection/api")
        logger.error("python server.py")
        sys.exit(1)
    
    # Stream logs
    log_file = Path(args.log_file)
    streamer.stream_file(log_file, session_id=args.session_id, max_logs=args.max_logs)


if __name__ == "__main__":
    main()
