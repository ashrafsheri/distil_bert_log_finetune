#!/bin/bash

# Demo script for Adaptive Online Learning System
# Shows all 3 phases: WARMUP → TRAINING → FULL ENSEMBLE

echo "========================================================================"
echo "ADAPTIVE ONLINE LEARNING DEMO"
echo "========================================================================"
echo ""
echo "This demo will:"
echo "  1. Stream logs through adaptive API"
echo "  2. Show WARMUP phase (collecting templates)"
echo "  3. Show TRAINING phase (transformer learning)"
echo "  4. Show FULL ENSEMBLE phase (all 3 models active)"
echo ""
echo "Press Ctrl+C to stop streaming"
echo ""
echo "========================================================================"
echo ""

# Check if server is running
if ! curl -s http://localhost:8000/health > /dev/null; then
    echo "❌ Adaptive server not running!"
    echo ""
    echo "Start it in another terminal:"
    echo "  cd realtime_anomaly_detection/api"
    echo "  python server_adaptive.py"
    echo ""
    exit 1
fi

# Show initial status
echo "📊 Initial Status:"
curl -s http://localhost:8000/status | python -m json.tool
echo ""
echo "========================================================================"
echo ""
echo "🚀 Starting log stream..."
echo ""

# Stream logs
cd streaming
python log_streamer.py \
    --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log \
    --delay 0.005

# Show final stats
echo ""
echo "========================================================================"
echo "📊 Final Status:"
curl -s http://localhost:8000/status | python -m json.tool
