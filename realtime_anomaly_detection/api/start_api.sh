#!/bin/bash
# Start the API server

cd "$(dirname "$0")"

echo "Starting Real-time Anomaly Detection API..."
echo "API will be available at: http://localhost:8000"
echo "Logs: api_server.log"
echo ""

python server.py 2>&1 | tee api_server.log
