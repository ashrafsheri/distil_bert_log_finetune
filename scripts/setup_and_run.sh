#!/bin/bash
# Complete setup and execution guide for log generation

cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║         NEXUS MXP LOG GENERATOR - QUICK START GUIDE         ║
╔══════════════════════════════════════════════════════════════╗

This guide will help you set up and run the log generator for
training your LogGuard anomaly detection model.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 PREREQUISITES

Before running the log generator, ensure:

1. ✅ Backend API is running (http://localhost:5000)
2. ✅ Nginx is running and logging to /var/log/nginx/access.log
3. ✅ Fluent-bit service is active and configured
4. ✅ LogGuard server is accessible and processing logs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 STEP 1: INSTALL DEPENDENCIES

EOF

echo "Checking Python installation..."
if command -v python3 &> /dev/null; then
    echo "✅ Python3 is installed: $(python3 --version)"
else
    echo "❌ Python3 not found. Please install Python 3.7 or higher."
    exit 1
fi

echo ""
echo "Do you want to install dependencies now? (y/n)"
read -p "> " install_deps

if [ "$install_deps" = "y" ] || [ "$install_deps" = "Y" ]; then
    echo ""
    echo "Installing Python dependencies..."
    cd "$(dirname "$0")"
    pip3 install -r requirements.txt
    echo "✅ Dependencies installed"
fi

cat << 'EOF'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 STEP 2: VERIFY SERVICES

EOF

echo "Checking backend API..."
if curl -s -f http://localhost:5000/api/gcp?page=1&limit=1 > /dev/null 2>&1; then
    echo "✅ Backend API is accessible at http://localhost:5000"
else
    echo "⚠️  Backend API is not responding. Please start it:"
    echo "   cd backend && npm start"
fi

echo ""
echo "Checking Nginx..."
if systemctl is-active --quiet nginx 2>/dev/null; then
    echo "✅ Nginx is running"
elif pgrep nginx > /dev/null; then
    echo "✅ Nginx is running"
else
    echo "⚠️  Nginx is not running. Please start it:"
    echo "   sudo systemctl start nginx"
fi

echo ""
echo "Checking Fluent-bit..."
if systemctl is-active --quiet fluent-bit 2>/dev/null; then
    echo "✅ Fluent-bit is running"
else
    echo "⚠️  Fluent-bit is not running. Please start it:"
    echo "   sudo systemctl start fluent-bit"
fi

cat << 'EOF'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 STEP 3: CHOOSE YOUR OPTION

Select what you want to do:

1) Quick Test (1,000 logs, ~1-2 minutes)
   - Perfect for testing the setup
   - Verify everything is working
   
2) Medium Run (10,000 logs, ~10-15 minutes)
   - Good for initial model warmup
   - Triggers model training phase
   
3) Production Run (100,000 logs, ~45-60 minutes)
   - Full dataset for comprehensive training
   - Recommended for production deployment
   
4) Custom Configuration
   - Set your own parameters
   
5) Test Attack Patterns Only
   - Verify attack detection without bulk generation
   
6) Monitor Logs in Real-time
   - Watch logs and Fluent-bit metrics
   
7) Exit

EOF

read -p "Enter your choice (1-7): " choice

cd "$(dirname "$0")"

case $choice in
    1)
        echo ""
        echo "Starting quick test..."
        ./quick_test.sh
        ;;
    2)
        echo ""
        echo "Starting medium run (10,000 logs)..."
        python3 log_generator.py --target 10000 --attack-ratio 0.15
        ;;
    3)
        echo ""
        echo "Starting production run..."
        ./production_run.sh
        ;;
    4)
        echo ""
        read -p "Enter target number of logs: " target
        read -p "Enter attack ratio (0.0-1.0, default 0.15): " ratio
        ratio=${ratio:-0.15}
        echo ""
        echo "Starting custom run with $target logs and $ratio attack ratio..."
        python3 log_generator.py --target $target --attack-ratio $ratio
        ;;
    5)
        echo ""
        echo "Testing attack patterns..."
        python3 test_attacks.py
        ;;
    6)
        echo ""
        echo "Starting real-time monitor..."
        ./monitor.sh
        ;;
    7)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting..."
        exit 1
        ;;
esac

cat << 'EOF'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ NEXT STEPS

1. Monitor your LogGuard dashboard to see incoming logs
2. Check log count in your organization
3. Wait for model training to begin (at 10k logs)
4. Monitor for email notification when student model is ready

To monitor in real-time:
  ./monitor.sh

To check Fluent-bit status:
  sudo systemctl status fluent-bit

To view nginx access logs:
  sudo tail -f /var/log/nginx/access.log

To check Fluent-bit metrics:
  curl http://localhost:2020/api/v1/metrics

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF
