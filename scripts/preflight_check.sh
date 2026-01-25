#!/bin/bash
# Pre-flight check - verify all systems are ready before log generation

echo "╔══════════════════════════════════════════════════════╗"
echo "║     PRE-FLIGHT CHECK - System Readiness             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

CHECKS_PASSED=0
CHECKS_FAILED=0

# Function to check and report
check() {
    if [ $1 -eq 0 ]; then
        echo "✅ $2"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "❌ $2"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
        if [ ! -z "$3" ]; then
            echo "   Fix: $3"
        fi
    fi
}

echo "Checking prerequisites..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check Python
python3 --version > /dev/null 2>&1
check $? "Python 3 is installed" "Install Python: sudo apt install python3"

# Check pip
pip3 --version > /dev/null 2>&1
check $? "pip3 is available" "Install pip: sudo apt install python3-pip"

# Check requests library
python3 -c "import requests" > /dev/null 2>&1
check $? "Python requests library installed" "Run: pip3 install -r requirements.txt"

echo ""
echo "Checking services..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check Backend API
curl -s -f https://nexusmxp.com/api/gcp?page=1&limit=1 > /dev/null 2>&1
check $? "Backend API is responding (https://nexusmxp.com)" "Check if nexusmxp.com is accessible"

# Check Nginx
if systemctl is-active --quiet nginx 2>/dev/null || pgrep nginx > /dev/null; then
    check 0 "Nginx web server is running"
else
    check 1 "Nginx web server is running" "Start nginx: sudo systemctl start nginx"
fi

# Check Nginx access log
if [ -f "/var/log/nginx/access.log" ]; then
    if [ -r "/var/log/nginx/access.log" ]; then
        check 0 "Nginx access log is accessible"
    else
        check 1 "Nginx access log is readable" "Check permissions on /var/log/nginx/access.log"
    fi
else
    check 1 "Nginx access log exists" "Create log file or check nginx configuration"
fi

# Check Fluent-bit
if systemctl is-active --quiet fluent-bit 2>/dev/null; then
    check 0 "Fluent-bit service is active"
else
    check 1 "Fluent-bit service is active" "Start fluent-bit: sudo systemctl start fluent-bit"
fi

# Check Fluent-bit HTTP server
curl -s http://localhost:2020/api/v1/metrics > /dev/null 2>&1
check $? "Fluent-bit HTTP server responding" "Check fluent-bit configuration"

echo ""
echo "Checking Fluent-bit configuration..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if API key is configured
if sudo grep -q "X-API-Key" /etc/fluent-bit/fluent-bit.conf 2>/dev/null; then
    check 0 "Fluent-bit has API key configured"
else
    check 1 "Fluent-bit has API key configured" "Configure API key in /etc/fluent-bit/fluent-bit.conf"
fi

# Check if LogGuard endpoint is configured
if sudo grep -q "/api/v1/logs/agent/send-logs" /etc/fluent-bit/fluent-bit.conf 2>/dev/null; then
    check 0 "Fluent-bit has LogGuard endpoint configured"
else
    check 1 "Fluent-bit has LogGuard endpoint configured" "Update URI in /etc/fluent-bit/fluent-bit.conf"
fi

echo ""
echo "Checking LogGuard connectivity..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Extract LogGuard host from config
LOGGUARD_HOST=$(sudo grep -A 5 "\[OUTPUT\]" /etc/fluent-bit/fluent-bit.conf 2>/dev/null | grep "Host" | head -1 | awk '{print $2}')
LOGGUARD_PORT=$(sudo grep -A 5 "\[OUTPUT\]" /etc/fluent-bit/fluent-bit.conf 2>/dev/null | grep "Port" | head -1 | awk '{print $2}')

if [ ! -z "$LOGGUARD_HOST" ] && [ ! -z "$LOGGUARD_PORT" ]; then
    echo "LogGuard server: $LOGGUARD_HOST:$LOGGUARD_PORT"
    
    # Test connectivity
    timeout 5 bash -c "cat < /dev/null > /dev/tcp/$LOGGUARD_HOST/$LOGGUARD_PORT" 2>/dev/null
    check $? "Can connect to LogGuard server" "Check network connectivity and firewall"
else
    check 1 "LogGuard server configuration found" "Check /etc/fluent-bit/fluent-bit.conf"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "RESULTS:"
echo "  ✅ Passed: $CHECKS_PASSED"
echo "  ❌ Failed: $CHECKS_FAILED"
echo ""

if [ $CHECKS_FAILED -eq 0 ]; then
    echo "🎉 All checks passed! System is ready for log generation."
    echo ""
    echo "You can now run:"
    echo "  ./quick_test.sh        - Quick test (1k logs)"
    echo "  ./production_run.sh    - Full run (100k logs)"
    echo "  ./setup_and_run.sh     - Interactive menu"
    echo ""
    exit 0
else
    echo "⚠️  Some checks failed. Please fix the issues above before proceeding."
    echo ""
    echo "Common fixes:"
    echo "  1. Install dependencies: pip3 install -r requirements.txt"
    echo "  2. Start backend: cd ../backend && npm start"
    echo "  3. Start nginx: sudo systemctl start nginx"
    echo "  4. Start fluent-bit: sudo systemctl start fluent-bit"
    echo ""
    exit 1
fi
