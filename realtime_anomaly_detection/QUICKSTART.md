# 🚀 Quick Start Guide - Real-time Log Anomaly Detection

## ✅ Prerequisites

The system is ready to use! All model files are already exported in:
```
artifacts/ensemble_model_export/
├── transformer_model.pt      # Transformer model (65 MB)
├── template_vocab.json        # Vocabulary (23,705 templates)
├── isolation_forest.pkl       # Isolation Forest (100 estimators)
├── model_config.json          # Configuration
└── README.md                  # Model documentation
```

## 📦 Installation

Install required dependencies (only needed once):

```bash
cd realtime_anomaly_detection
pip install -r requirements.txt
```

Or install manually:
```bash
pip install fastapi uvicorn[standard] pydantic requests torch scikit-learn numpy
```

## 🎯 Usage - 3 Steps

### Step 1: Test the System

```bash
cd realtime_anomaly_detection
python test_system.py
```

This will:
- ✅ Load all models (Transformer, Isolation Forest, Rule-based)
- ✅ Test detection on sample logs
- ✅ Show example anomaly detections

Expected output:
```
1. 🟢 NORMAL (score: 0.375)
   Log: GET / HTTP/1.1 200

2. 🔴 ANOMALY (score: 0.650)
   Log: GET /search?q=<script>alert(1)</script> HTTP/1.1
   Rule-based: ['xss']
```

### Step 2: Start the API Server

**Terminal 1** - Start the API:
```bash
cd realtime_anomaly_detection/api
python server.py
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
✓ Ensemble detector initialized successfully!
```

**Test the API:**
```bash
curl http://localhost:8000/health
```

### Step 3: Stream Logs in Real-time

**Terminal 2** - Start streaming:
```bash
cd realtime_anomaly_detection/streaming

# Stream first 100 logs with 0.1s delay
python log_streamer.py \
  --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log \
  --delay 0.1 \
  --max-logs 100
```

**Real-time Output:**
```
================================================================================
REAL-TIME LOG ANOMALY DETECTION
================================================================================

[NORMAL ] [14:23:01] Score: 0.214 GET / HTTP/1.1 200
[NORMAL ] [14:23:02] Score: 0.186 GET /favicon.ico HTTP/1.1 200
[ANOMALY] [14:23:03] Score: 0.892 [R:sql_injection | I:8.45 | T:15.32] GET /admin' OR '1'='1 HTTP/1.1 403
[NORMAL ] [14:23:04] Score: 0.198 GET /api/users HTTP/1.1 200
[ANOMALY] [14:23:05] Score: 0.956 [R:xss | I:7.23] GET /search?q=<script>alert(1)</script> HTTP/1.1 200

================================================================================
STREAMING STATISTICS
================================================================================
  Total logs processed: 100
  Normal logs: 85 (85.0%)
  Anomalies detected: 15 (15.0%)
================================================================================
```

## 🎨 Color Legend

- 🟢 **GREEN** = Normal traffic
- 🔴 **RED** = Detected anomaly/attack
- 🟣 **MAGENTA** = Detection method details:
  - `R:` = Rule-based (attack type)
  - `I:` = Isolation Forest score
  - `T:` = Transformer score

## ⚙️ Configuration

### Streaming Options

```bash
python log_streamer.py \
  --log-file <path_to_log_file> \
  --delay <seconds>              # Delay between logs (default: 0.1)
  --max-logs <number>            # Max logs to process (default: all)
  --api-url <url>                # API URL (default: http://localhost:8000)
  --session-id <id>              # Fixed session ID (default: use IP from log)
```

### Examples

**Fast streaming (10 logs/second):**
```bash
python log_streamer.py --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log --delay 0.01
```

**Process only 50 logs:**
```bash
python log_streamer.py --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log --max-logs 50
```

**Custom API URL:**
```bash
python log_streamer.py --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log --api-url http://192.168.1.100:8000
```

## 📊 API Endpoints

### Health Check
```bash
GET http://localhost:8000/health
```

### Single Log Detection
```bash
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "192.168.1.1 - - [22/Oct/2025:10:30:45 +0000] \"GET /admin'\'' OR '\''1'\''='\''1 HTTP/1.1\" 403 0"
  }'
```

### Batch Detection
```bash
curl -X POST http://localhost:8000/detect/batch \
  -H "Content-Type: application/json" \
  -d '{
    "log_lines": [
      "192.168.1.1 - - [date] \"GET / HTTP/1.1\" 200 1234",
      "192.168.1.1 - - [date] \"GET /admin HTTP/1.1\" 200 5678"
    ]
  }'
```

### Interactive API Docs
Visit: http://localhost:8000/docs

## 🐛 Troubleshooting

### API won't start
```bash
# Check if models exist
ls -lh ../artifacts/ensemble_model_export/

# Should see:
# - transformer_model.pt (65 MB)
# - template_vocab.json (4.1 MB)
# - isolation_forest.pkl (1 MB)
# - model_config.json

# If missing, run notebook 07 to export models
```

### Streaming shows errors
```bash
# 1. Check API is running
curl http://localhost:8000/health

# 2. Restart API if needed
# Press Ctrl+C in API terminal, then:
python server.py

# 3. Check log file exists
ls -lh ../../data/apache_logs/synthetic_nodejs_apache_10k.log
```

### Low detection rate
The model is trained on specific attack patterns. To improve:
1. Add custom rules in `models/ensemble_detector.py` → `RuleBasedDetector`
2. Adjust threshold in `artifacts/ensemble_model_export/model_config.json`
3. Retrain transformer on your specific log format

## 📈 Expected Performance

Based on `synthetic_nodejs_apache_10k.log`:
- **Accuracy**: 94.7%
- **Precision**: 100% (rule-based), 85.9% (ensemble)
- **Recall**: 46% (primarily signature-based attacks)

**Attack Detection:**
- ✅ SQL Injection: 100%
- ✅ XSS: 100%
- ✅ Path Traversal: 100%
- ❌ Scanning: 0% (add custom rules)
- ❌ Brute Force: 0% (add custom rules)

## 🔄 Next Steps

1. **Monitor production logs**: Point the streamer to your production log files
2. **Add custom rules**: Edit `RuleBasedDetector` for domain-specific attacks
3. **Tune thresholds**: Adjust in `model_config.json` for your baseline
4. **Deploy to production**: Use Docker/K8s to scale the API
5. **Add alerts**: Integrate with PagerDuty, Slack, etc.

## 💡 Tips

- Use `--delay 0.01` for faster replay of historical logs
- Use `--max-logs 100` for quick tests
- Monitor API logs for performance metrics
- Run API on GPU for faster transformer inference (change `device='cuda'`)

## 🆘 Support

If you encounter issues:
1. Run `python test_system.py` to verify setup
2. Check model files exist in `artifacts/ensemble_model_export/`
3. Verify Python packages are installed: `pip list | grep -E '(fastapi|torch|sklearn)'`
4. Check API logs in the terminal running `server.py`

---

**Ready to detect anomalies in real-time!** 🚀

Start with:
```bash
# Terminal 1
cd realtime_anomaly_detection/api && python server.py

# Terminal 2 (new terminal)
cd realtime_anomaly_detection/streaming
python log_streamer.py --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log --max-logs 100
```
