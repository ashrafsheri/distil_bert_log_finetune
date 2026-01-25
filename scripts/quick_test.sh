#!/bin/bash
# Quick test script - generates 1000 logs for testing

echo "Running quick test - generating 1000 logs..."
echo "This should take about 1-2 minutes"
echo ""

python3 log_generator.py --target 1000 --attack-ratio 0.15

echo ""
echo "Quick test complete! Check your nginx access logs:"
echo "  sudo tail -n 50 /var/log/nginx/access.log"
echo ""
echo "Check Fluent-bit is sending logs:"
echo "  sudo journalctl -u fluent-bit -n 20"
