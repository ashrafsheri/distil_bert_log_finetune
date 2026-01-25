#!/bin/bash
# Production run - generates 100k logs for model training

echo "=========================================="
echo "  Production Log Generation"
echo "=========================================="
echo "Target: 100,000 requests"
echo "Attack ratio: 15%"
echo "Estimated time: 45-60 minutes"
echo ""
echo "This will generate comprehensive logs for"
echo "training the anomaly detection model."
echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."
echo ""

# Create logs directory if it doesn't exist
mkdir -p ../logs

# Start generation with output logging
python3 log_generator.py --target 100000 --attack-ratio 0.15 2>&1 | tee ../logs/generation_$(date +%Y%m%d_%H%M%S).log

echo ""
echo "=========================================="
echo "  Generation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Verify logs in nginx: sudo tail /var/log/nginx/access.log"
echo "2. Check Fluent-bit metrics: curl http://localhost:2020/api/v1/metrics"
echo "3. Monitor LogGuard dashboard for incoming logs"
echo "4. Wait for model training to begin (at 10k logs)"
echo ""
