#!/bin/bash
# Stream logs with real-time anomaly detection

cd "$(dirname "$0")"

# Default log file
LOG_FILE=${1:-"../../data/apache_logs/synthetic_nodejs_apache_10k.log"}
DELAY=${2:-"0.1"}
MAX_LOGS=${3:-"1000"}

echo "=========================================="
echo "Real-time Log Streaming"
echo "=========================================="
echo "Log file: $LOG_FILE"
echo "Delay: ${DELAY}s"
echo "Max logs: $MAX_LOGS"
echo ""
echo "Make sure API server is running!"
echo "  (In another terminal: cd ../api && ./start_api.sh)"
echo ""

python log_streamer.py \
  --log-file "$LOG_FILE" \
  --delay "$DELAY" \
  --max-logs "$MAX_LOGS"
