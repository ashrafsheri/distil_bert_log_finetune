#!/bin/bash
# Start the Adaptive API server (with online learning)

cd "$(dirname "$0")"

echo "Starting Adaptive Real-time Anomaly Detection API..."
echo "API will be available at: http://localhost:8000"
echo ""
echo "🔄 ADAPTIVE MODE - Online Learning Enabled"
echo "  Phase 1: First 50,000 logs - Rule-based + Isolation Forest"
echo "  Phase 2: Training Transformer in background"
echo "  Phase 3: Full ensemble (3 models) after training"
echo ""
echo "Logs: api_adaptive.log"
echo ""

python server_adaptive.py 2>&1 | tee api_adaptive.log
