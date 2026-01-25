#!/bin/bash
# Monitor log generation and Fluent-bit in real-time

echo "=========================================="
echo "  Real-time Log Monitoring Dashboard"
echo "=========================================="
echo ""
echo "This script monitors:"
echo "  • Nginx access logs (new requests)"
echo "  • Fluent-bit service status"
echo "  • Fluent-bit metrics (sends/retries)"
echo ""
echo "Press Ctrl+C to stop monitoring"
echo ""
sleep 2

while true; do
    clear
    echo "=========================================="
    echo "  Log Monitoring - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================="
    echo ""
    
    # Show last 5 nginx access log entries
    echo "📊 Latest Nginx Access Logs (last 5):"
    echo "---"
    sudo tail -n 5 /var/log/nginx/access.log 2>/dev/null | while read line; do
        echo "  $line"
    done
    echo ""
    
    # Show Fluent-bit status
    echo "🔧 Fluent-bit Service Status:"
    echo "---"
    systemctl is-active fluent-bit >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "  ✅ Status: RUNNING"
    else
        echo "  ❌ Status: STOPPED"
    fi
    echo ""
    
    # Show Fluent-bit metrics
    echo "📈 Fluent-bit Metrics:"
    echo "---"
    metrics=$(curl -s http://localhost:2020/api/v1/metrics 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "$metrics" | python3 -m json.tool 2>/dev/null | grep -E "(proc_records|retries|errors|dropped)" | while read line; do
            echo "  $line"
        done
    else
        echo "  ⚠️  Could not fetch metrics (is Fluent-bit HTTP server running?)"
    fi
    echo ""
    
    # Show recent Fluent-bit logs (errors/warnings only)
    echo "⚠️  Recent Fluent-bit Issues (last 5 min):"
    echo "---"
    recent_issues=$(sudo journalctl -u fluent-bit --since="5 minutes ago" --no-pager 2>/dev/null | grep -i -E "(error|warn|fail)" | tail -n 3)
    if [ -z "$recent_issues" ]; then
        echo "  ✅ No errors or warnings"
    else
        echo "$recent_issues" | while read line; do
            echo "  $line"
        done
    fi
    echo ""
    
    # Count logs in last minute
    echo "📊 Request Rate (last minute):"
    echo "---"
    one_min_ago=$(date -d '1 minute ago' '+%d/%b/%Y:%H:%M' 2>/dev/null || date -v-1M '+%d/%b/%Y:%H:%M')
    recent_count=$(sudo grep "$one_min_ago" /var/log/nginx/access.log 2>/dev/null | wc -l)
    echo "  Requests: $recent_count in the last minute"
    echo ""
    
    echo "=========================================="
    echo "Refreshing in 5 seconds..."
    sleep 5
done
