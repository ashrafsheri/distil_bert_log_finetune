"""
LogShipperAgent - Main Agent Class
Reads Apache logs and sends them to backend with acknowledgment tracking
"""

import os
import sys
import time
import asyncio
import aiohttp
import logging
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
import signal
import threading
from dataclasses import dataclass
from dotenv import load_dotenv

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from raw_log_reader import RawLogReader
from sliding_window import SlidingWindow, PendingBatch
from ack_tracker import AcknowledgmentTracker
from position_tracker import PositionTracker

@dataclass
class AgentConfig:
    """Configuration for LogShipperAgent"""
    apache_log_path: str
    backend_url: str
    api_endpoint: str
    poll_interval: int
    batch_size: int
    max_retries: int
    retry_delay: int
    window_size: int
    ack_timeout: int
    log_format: str
    enable_anomaly_detection: bool
    anomaly_threshold: float
    debug: bool
    log_level: str

class LogShipperAgent:
    """Main LogShipperAgent class"""
    
    def __init__(self, config_file: str = ".env"):
        """
        Initialize LogShipperAgent
        
        Args:
            config_file: Path to configuration file
        """
        # Load environment variables from .env file
        load_dotenv(config_file)
        
        # Create configuration from environment variables
        self.config = AgentConfig(
            apache_log_path=os.getenv('APACHE_LOG_PATH', '/var/log/apache2/access.log'),
            backend_url=os.getenv('BACKEND_URL', 'http://localhost:8000'),
            api_endpoint=os.getenv('API_ENDPOINT', '/api/v1/agent/sendLogs'),
            poll_interval=int(os.getenv('POLL_INTERVAL', '5')),
            batch_size=int(os.getenv('BATCH_SIZE', '100')),
            max_retries=int(os.getenv('MAX_RETRIES', '3')),
            retry_delay=int(os.getenv('RETRY_DELAY', '2')),
            window_size=int(os.getenv('WINDOW_SIZE', '1000')),
            ack_timeout=int(os.getenv('ACK_TIMEOUT', '30')),
            log_format=os.getenv('LOG_FORMAT', 'combined'),
            enable_anomaly_detection=os.getenv('ENABLE_ANOMALY_DETECTION', 'true').lower() == 'true',
            anomaly_threshold=float(os.getenv('ANOMALY_THRESHOLD', '0.8')),
            debug=os.getenv('DEBUG', 'false').lower() == 'true',
            log_level=os.getenv('LOG_LEVEL', 'INFO')
        )
        
        self.logger = self._setup_logging()
        
        # Initialize components
        self.raw_reader = RawLogReader()
        self.position_tracker = PositionTracker()
        self.sliding_window = SlidingWindow(
            window_size=self.config.window_size,
            ack_timeout=self.config.ack_timeout
        )
        self.ack_tracker = AcknowledgmentTracker()
        
        # State tracking
        self.file_position = 0
        self.running = False
        self.stats = {
            "logs_processed": 0,
            "batches_sent": 0,
            "acknowledgments_received": 0,
            "errors": 0,
            "start_time": None
        }
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        self.logger.info("LogShipperAgent initialized successfully")
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('log_shipper.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        return logging.getLogger(__name__)
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, shutting down gracefully...")
            self.stop()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def start(self):
        """Start the LogShipperAgent"""
        self.logger.info("Starting LogShipperAgent...")
        self.running = True
        self.stats["start_time"] = datetime.now()
        
        # Initialize file position from tracker
        self.file_position = self.position_tracker.get_position(self.config.apache_log_path)
        
        # Start main processing loop
        try:
            await self._main_loop()
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
            raise
        finally:
            await self._cleanup()
    
    async def _main_loop(self):
        """Main processing loop"""
        while self.running:
            try:
                # Process new logs
                await self._process_logs()
                
                # Handle acknowledgments
                await self._handle_acknowledgments()
                
                # Handle retries
                await self._handle_retries()
                
                # Cleanup old data
                self._cleanup_old_data()
                
                # Wait for next poll
                await asyncio.sleep(self.config.poll_interval)
                
            except Exception as e:
                self.logger.error(f"Error in main loop iteration: {e}")
                self.stats["errors"] += 1
                await asyncio.sleep(self.config.retry_delay)
    
    async def _process_logs(self):
        """Process new logs from file"""
        try:
            # Read new raw logs from file
            raw_logs, new_position, was_rotated = self.raw_reader.read_new_logs(
                self.config.apache_log_path, 
                self.file_position,
                max_lines=self.config.batch_size
            )
            
            if raw_logs:
                self.logger.info(f"Read {len(raw_logs)} new raw log entries")
                self.stats["logs_processed"] += len(raw_logs)
                
                # Update file position
                self.file_position = new_position
                self.position_tracker.update_position(self.config.apache_log_path, new_position)
                
                # Handle file rotation
                if was_rotated:
                    self.logger.info("File rotation detected, resetting position tracking")
                    self.position_tracker.handle_file_rotation(self.config.apache_log_path)
                
                # Process logs in batches
                await self._process_log_batches(raw_logs)
            
        except Exception as e:
            self.logger.error(f"Error processing logs: {e}")
            self.stats["errors"] += 1
    
    async def _process_log_batches(self, raw_logs: List[str]):
        """Process logs in batches"""
        for i in range(0, len(raw_logs), self.config.batch_size):
            batch_logs = raw_logs[i:i + self.config.batch_size]
            
            # Add batch to sliding window
            batch_id = self.sliding_window.add_batch(
                batch_logs, 
                max_retries=self.config.max_retries
            )
            
            if batch_id:
                # Mark as pending acknowledgment
                self.ack_tracker.mark_pending(batch_id)
                
                # Send batch to backend
                await self._send_batch(batch_id, batch_logs)
    
    async def _send_batch(self, batch_id: str, raw_logs: List[str]):
        """Send batch to backend"""
        try:
            # Prepare batch data with raw logs
            batch_data = {
                "batch_id": batch_id,
                "raw_logs": raw_logs
            }
            
            # Send to backend
            start_time = time.time()
            success = await self._send_to_backend(batch_data)
            response_time = time.time() - start_time
            
            # Record acknowledgment
            self.ack_tracker.record_acknowledgment(
                batch_id=batch_id,
                success=success,
                response_time=response_time,
                error_message=None if success else "Backend request failed"
            )
            
            if success:
                self.stats["batches_sent"] += 1
                self.stats["acknowledgments_received"] += 1
                self.logger.info(f"Successfully sent batch {batch_id}")
            else:
                self.logger.error(f"Failed to send batch {batch_id}")
                
        except Exception as e:
            self.logger.error(f"Error sending batch {batch_id}: {e}")
            self.ack_tracker.record_acknowledgment(
                batch_id=batch_id,
                success=False,
                response_time=0,
                error_message=str(e)
            )
            self.stats["errors"] += 1
    
    async def _send_to_backend(self, batch_data: Dict) -> bool:
        """Send batch data to backend API"""
        try:
            url = f"{self.config.backend_url}{self.config.api_endpoint}"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=batch_data,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        return True
                    else:
                        self.logger.error(f"Backend returned status {response.status}")
                        return False
                        
        except asyncio.TimeoutError:
            self.logger.error("Backend request timed out")
            return False
        except Exception as e:
            self.logger.error(f"Error sending to backend: {e}")
            return False
    
    async def _handle_acknowledgments(self):
        """Handle acknowledgment processing"""
        # This is where you would implement acknowledgment handling
        # For now, we'll just log the status
        pending_batches = self.ack_tracker.get_pending_batches()
        if pending_batches:
            self.logger.debug(f"Pending acknowledgments: {len(pending_batches)}")
    
    async def _handle_retries(self):
        """Handle retry logic for failed batches"""
        retry_batches = self.sliding_window.get_retry_batches()
        
        for batch in retry_batches:
            self.logger.info(f"Retrying batch {batch.batch_id}")
            await self._send_batch(batch.batch_id, batch.raw_logs)
    
    def _cleanup_old_data(self):
        """Clean up old data to prevent memory leaks"""
        # Cleanup old acknowledgments
        self.ack_tracker.cleanup_old_records(max_age_hours=24)
        
        # Cleanup sliding window
        self.sliding_window.cleanup_old_acknowledgments(max_age_hours=24)
    
    async def _cleanup(self):
        """Cleanup resources on shutdown"""
        self.logger.info("Cleaning up resources...")
        
        # Log final statistics
        self._log_final_stats()
        
        # Close any open connections
        # (aiohttp sessions are closed automatically)
    
    def _log_final_stats(self):
        """Log final statistics"""
        stats = self.stats.copy()
        if stats["start_time"]:
            runtime = datetime.now() - stats["start_time"]
            stats["runtime_seconds"] = runtime.total_seconds()
        
        ack_stats = self.ack_tracker.get_acknowledgment_stats()
        window_stats = self.sliding_window.get_stats()
        
        self.logger.info("Final Statistics:")
        self.logger.info(f"  Logs Processed: {stats['logs_processed']}")
        self.logger.info(f"  Batches Sent: {stats['batches_sent']}")
        self.logger.info(f"  Acknowledgments: {stats['acknowledgments_received']}")
        self.logger.info(f"  Errors: {stats['errors']}")
        self.logger.info(f"  Success Rate: {ack_stats['success_rate']:.2%}")
        self.logger.info(f"  Avg Response Time: {ack_stats['average_response_time']:.2f}s")
        self.logger.info(f"  Pending Batches: {window_stats['pending_batches']}")
    
    def stop(self):
        """Stop the LogShipperAgent"""
        self.logger.info("Stopping LogShipperAgent...")
        self.running = False
    
    def get_status(self) -> Dict:
        """Get current status of the agent"""
        return {
            "running": self.running,
            "stats": self.stats,
            "acknowledgment_stats": self.ack_tracker.get_acknowledgment_stats(),
            "window_stats": self.sliding_window.get_stats(),
            "health": self.ack_tracker.get_health_status()
        }

async def main():
    """Main entry point"""
    try:
        agent = LogShipperAgent()
        await agent.start()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
