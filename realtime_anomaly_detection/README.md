# Real-time Log Anomaly Detection System

A complete real-time log anomaly detection system using ensemble learning (Transformer + Rule-based + Isolation Forest) with REST API and live streaming visualization.

## 🎯 Features

- **Ensemble Detection**: Combines 3 detection methods:
  - 🤖 **Transformer**: Sequence-based behavioral analysis
  - 📋 **Rule-based**: Pattern matching for known attacks (SQL injection, XSS, path traversal, command injection)
  - 📊 **Isolation Forest**: Statistical anomaly detection
  
- **REST API**: FastAPI server for scalable inference
- **Real-time Streaming**: Simulates live log streaming with color-coded terminal output
- **Session-aware**: Maintains context windows per IP/session for sequence analysis

## 📁 Project Structure

```
realtime_anomaly_detection/
├── api/
│   └── server.py              # FastAPI inference server
├── streaming/
│   └── log_streamer.py        # Real-time log streaming simulator
├── models/
│   └── ensemble_detector.py  # Ensemble detection logic
└── README.md
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install fastapi uvicorn requests torch scikit-learn numpy pydantic
```

### 2. Start the API Server

```bash
cd realtime_anomaly_detection/api
python server.py
```

The API will start on `http://localhost:8000`

### 3. Test the API

Visit `http://localhost:8000/docs` for interactive API documentation.

Or test with curl:

```bash
curl -X POST "http://localhost:8000/detect" \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "192.168.1.1 - - [22/Oct/2025:10:30:45 +0000] \"GET /admin'\'' OR '\''1'\''='\''1 HTTP/1.1\" 403 1234"
  }'
```

### 4. Stream Logs in Real-time

```bash
cd realtime_anomaly_detection/streaming

# Stream Apache logs with 0.1s delay
python log_streamer.py \
  --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log \
  --delay 0.1

# Stream first 100 logs only
python log_streamer.py \
  --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log \
  --delay 0.05 \
  --max-logs 100

# Stream with custom session ID
python log_streamer.py \
  --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log \
  --session-id "test_session"
```

## 📊 Real-time Output Example

```
================================================================================
REAL-TIME LOG ANOMALY DETECTION
================================================================================
  Log file: synthetic_nodejs_apache_10k.log
  API: http://localhost:8000
  Delay: 0.1s between logs
================================================================================

[NORMAL ] [10:30:45] Score: 0.214 GET / HTTP/1.1 200
[NORMAL ] [10:30:46] Score: 0.186 GET /favicon.ico HTTP/1.1 200
[ANOMALY] [10:30:47] Score: 0.892 [R:sql_injection | I:8.45 | T:15.32] GET /admin' OR '1'='1 HTTP/1.1 403
[NORMAL ] [10:30:48] Score: 0.198 GET /api/users HTTP/1.1 200
[ANOMALY] [10:30:49] Score: 0.956 [R:xss | I:7.23] GET /search?q=<script>alert(1)</script> HTTP/1.1 200

================================================================================
STREAMING STATISTICS
================================================================================
  Total logs processed: 100
  Normal logs: 85 (85.0%)
  Anomalies detected: 15 (15.0%)
================================================================================
```

**Color Legend:**
- 🟢 **GREEN** = Normal traffic
- 🔴 **RED** = Detected anomaly/attack
- 🟣 **MAGENTA** = Detection method details
  - `R:` = Rule-based (attack type)
  - `I:` = Isolation Forest score
  - `T:` = Transformer score

## 🔌 API Endpoints

### Health Check
```bash
GET /health
```

### Single Log Detection
```bash
POST /detect
{
  "log_line": "192.168.1.1 - - [date] \"GET /path HTTP/1.1\" 200 1234",
  "session_id": "optional_session_id"
}
```

### Batch Detection
```bash
POST /detect/batch
{
  "log_lines": ["log1", "log2", ...],
  "session_id": "optional_session_id"
}
```

### Reset Session
```bash
POST /reset/{session_id}
POST /reset/all
```

## 🛠️ Configuration

### Model Location
The API expects models in: `artifacts/ensemble_model_export/`

Required files:
- `transformer_model.pt` - Transformer checkpoint
- `template_vocab.json` - Template vocabulary
- `isolation_forest.pkl` - Isolation Forest model
- `model_config.json` - Configuration (threshold, etc.)

### Detection Parameters

Edit `models/ensemble_detector.py` to adjust:
- `window_size`: Sequence length for transformer (default: 20)
- `optimal_threshold`: Transformer anomaly threshold (default: from config)
- Ensemble weights (rule: 1.0, iso: 0.6, transformer: 0.7)

### Streaming Parameters

`log_streamer.py` options:
- `--delay`: Delay between logs in seconds (default: 0.1)
- `--max-logs`: Maximum logs to stream (default: all)
- `--session-id`: Fixed session ID (default: use IP from log)

## 📈 Performance

Based on `synthetic_nodejs_apache_10k.log`:
- **Accuracy**: 94.7%
- **Precision**: 100% (rule-based), 85.9% (ensemble)
- **Recall**: 46.1% (mainly signature-based attacks)
- **F1-Score**: 0.630

Attack type detection:
- ✅ SQL Injection: 100%
- ✅ XSS: 100%
- ✅ Path Traversal: 100%
- ❌ Scanning: 0% (add custom rules)
- ❌ Brute Force: 0% (add custom rules)

## 🔧 Troubleshooting

### API won't start
- Check model files exist in `artifacts/ensemble_model_export/`
- Verify PyTorch and scikit-learn are installed
- Check port 8000 is available

### Streaming shows all errors
- Ensure API server is running (`http://localhost:8000`)
- Test API with: `curl http://localhost:8000/health`
- Check network connectivity

### Low detection rate
- Adjust transformer threshold in `model_config.json`
- Add custom rule patterns in `RuleBasedDetector`
- Retrain models on domain-specific data

## 🎓 Development

### Add custom attack patterns

Edit `models/ensemble_detector.py` → `RuleBasedDetector`:

```python
self.custom_patterns = [
    r"pattern1",
    r"pattern2",
]
```

### Adjust ensemble weights

Edit `models/ensemble_detector.py` → `EnsembleAnomalyDetector.detect()`:

```python
weights.append(0.8)  # Increase transformer weight
```

### Change API port

Edit `api/server.py` → `main()`:

```python
uvicorn.run("server:app", host="0.0.0.0", port=9000)
```

## 📝 License

Part of the distil_shahreyar log anomaly detection project.

## 🤝 Contributing

To improve detection:
1. Collect more diverse training data
2. Add domain-specific rule patterns
3. Tune ensemble weights for your use case
4. Retrain transformer on your log format
