# 🚀 Real-time Log Anomaly Detection API

Production-ready REST API for detecting anomalies in Apache web server logs using an adaptive ensemble of machine learning models.

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [API Endpoints](#api-endpoints)
- [Docker Deployment](#docker-deployment)
- [API Usage Examples](#api-usage-examples)
- [Configuration](#configuration)
- [Monitoring](#monitoring)

---

## ✨ Features

- **Adaptive Online Learning**: Trains on YOUR log data for domain-specific detection
- **Ensemble Detection**: Combines 3 models (Rule-based, Isolation Forest, Transformer)
- **Real-time Processing**: Sub-second latency per request
- **Production Ready**: Docker support, health checks, logging
- **Scalable**: Stateless API design, horizontal scaling ready

---

## 🏗️ Architecture

### Detection Models

| Model | Type | Purpose | Active |
|-------|------|---------|--------|
| **Rule-based** | Signature | Pattern matching (SQL, XSS, etc.) | Always |
| **Isolation Forest** | Statistical | Anomaly detection on HTTP features | After warmup |
| **Transformer** | Sequence | Behavioral analysis | After training |

### Learning Phases

1. **Phase 1 - Warmup** (0-50k logs)
   - Rule-based detection only
   - Collecting baseline data
   
2. **Phase 2 - Training** (Background)
   - Train Isolation Forest on 50k samples
   - Train Transformer on collected templates
   
3. **Phase 3 - Ensemble** (50k+ logs)
   - All 3 models active
   - Maximum detection accuracy

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Model artifacts in `artifacts/ensemble_model_export/`

### Run with Docker Compose

```bash
# Navigate to the directory
cd realtime_anomaly_detection

# Start the API
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Stop the API
docker-compose down
```

The API will be available at `http://localhost:8000`

---

## 📡 API Endpoints

### 1. Root Endpoint

**GET** `/`

Get API information and available endpoints.

**Response:**
```json
{
  "message": "Adaptive Real-time Log Anomaly Detection API",
  "version": "2.0.0",
  "learning_mode": "online",
  "endpoints": {
    "health": "/health",
    "detect": "/detect (POST)",
    "detect_batch": "/detect/batch (POST)",
    "status": "/status"
  }
}
```

---

### 2. Health Check

**GET** `/health`

Check API health and learning status.

**Response:**
```json
{
  "status": "healthy",
  "phase": "warmup",
  "logs_processed": 12450,
  "transformer_ready": false,
  "active_models": 1
}
```

**Phase Values:**
- `warmup` - Collecting baseline (0-50k logs)
- `training` - Models training in background
- `ensemble` - All 3 models active
- `waiting` - Training complete, waiting for first request

---

### 3. Detection Status

**GET** `/status`

Get detailed learning and training status.

**Response:**
```json
{
  "logs_processed": 12450,
  "warmup_target": 50000,
  "warmup_complete": false,
  "training_in_progress": false,
  "isolation_forest_ready": false,
  "transformer_ready": false,
  "vocabulary_size": 8234,
  "training_sequences": 11920,
  "iso_training_samples": 12450,
  "active_models": {
    "rule_based": true,
    "isolation_forest": false,
    "transformer": false
  },
  "phase": "warmup"
}
```

---

### 4. Detect Single Log

**POST** `/detect`

Detect anomaly in a single log line.

**Request Body:**
```json
{
  "log_line": "192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] \"GET /admin' OR '1'='1 HTTP/1.1\" 403 1234",
  "session_id": "192.168.1.1"
}
```

**Parameters:**
- `log_line` (required): Apache log line (Common or Combined format)
- `session_id` (optional): Session identifier (defaults to IP address)

**Response:**
```json
{
  "is_anomaly": true,
  "anomaly_score": 0.956,
  "phase": "ensemble",
  "timestamp": "2025-10-22T10:30:48.123456",
  "details": {
    "logs_processed": 52341,
    "transformer_ready": true,
    "isolation_forest_ready": true,
    "rule_based": {
      "is_attack": true,
      "attack_types": ["sql_injection"],
      "confidence": 0.8,
      "patterns_matched": ["OR.*=.*"]
    },
    "isolation_forest": {
      "is_anomaly": 1,
      "score": 8.45,
      "status": "active"
    },
    "transformer": {
      "is_anomaly": 1,
      "score": 15.32,
      "status": "active"
    },
    "ensemble": {
      "score": 0.956,
      "votes": {
        "rule": 1,
        "iso": 1,
        "transformer": 1
      },
      "weights": {
        "rule": 0.8,
        "iso": 0.6,
        "transformer": 0.7
      },
      "active_models": 3
    },
    "log_data": {
      "ip": "192.168.1.1",
      "method": "GET",
      "path": "/admin' OR '1'='1",
      "protocol": "HTTP/1.1",
      "status": 403,
      "raw_line": "..."
    }
  }
}
```

---

### 5. Detect Batch

**POST** `/detect/batch`

Detect anomalies in multiple log lines (up to 100).

**Request Body:**
```json
{
  "log_lines": [
    "192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] \"GET / HTTP/1.1\" 200 1234",
    "192.168.1.2 - - [22/Oct/2025:10:30:49 +0000] \"GET /admin' OR '1'='1 HTTP/1.1\" 403 5678"
  ],
  "session_id": "batch_001"
}
```

**Response:**
```json
{
  "results": [
    {
      "is_anomaly": false,
      "anomaly_score": 0.214,
      "phase": "ensemble",
      "details": { ... }
    },
    {
      "is_anomaly": true,
      "anomaly_score": 0.956,
      "phase": "ensemble",
      "details": { ... }
    }
  ],
  "summary": {
    "total": 2,
    "anomalies": 1,
    "normal": 1,
    "anomaly_rate": 0.5
  }
}
```

---

## 🐳 Docker Deployment

### Option 1: Docker Compose (Recommended)

```bash
# Development
docker-compose up -d

# Production (with resource limits)
docker-compose -f docker-compose.prod.yml up -d
```

### Option 2: Manual Docker Build

```bash
# Build image
docker build -t anomaly-detection-api:latest -f Dockerfile ..

# Run container
docker run -d \
  --name anomaly-detection-api \
  -p 8000:8000 \
  -v $(pwd)/../artifacts/ensemble_model_export:/app/artifacts/ensemble_model_export:ro \
  -e MODEL_DIR=/app/artifacts/ensemble_model_export \
  -e WARMUP_LOGS=50000 \
  anomaly-detection-api:latest
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_DIR` | `/app/artifacts/ensemble_model_export` | Model artifacts directory |
| `WARMUP_LOGS` | `50000` | Number of logs for warmup phase |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `WORKERS` | `1` | Number of Uvicorn workers |

---

## 💻 API Usage Examples

### cURL Examples

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Detect Single Log
```bash
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 200 1234"
  }'
```

#### Detect Batch
```bash
curl -X POST http://localhost:8000/detect/batch \
  -H "Content-Type: application/json" \
  -d '{
    "log_lines": [
      "192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] \"GET / HTTP/1.1\" 200 1234",
      "192.168.1.2 - - [22/Oct/2025:10:30:49 +0000] \"GET /etc/passwd HTTP/1.1\" 403 5678"
    ]
  }'
```

#### Get Status
```bash
curl http://localhost:8000/status | jq .
```

---

### Python Examples

```python
import requests
import json

API_URL = "http://localhost:8000"

# Health check
response = requests.get(f"{API_URL}/health")
print(response.json())

# Detect single log
log_line = '192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] "GET /admin HTTP/1.1" 403 1234'
response = requests.post(
    f"{API_URL}/detect",
    json={"log_line": log_line}
)
result = response.json()

if result['is_anomaly']:
    print(f"🔴 ANOMALY DETECTED! Score: {result['anomaly_score']:.3f}")
    print(f"   Attack types: {result['details']['rule_based']['attack_types']}")
else:
    print(f"🟢 Normal traffic. Score: {result['anomaly_score']:.3f}")

# Detect batch
logs = [
    '192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] "GET / HTTP/1.1" 200 1234',
    '192.168.1.2 - - [22/Oct/2025:10:30:49 +0000] "GET /admin\' OR \'1\'=\'1 HTTP/1.1" 403 5678'
]

response = requests.post(
    f"{API_URL}/detect/batch",
    json={"log_lines": logs}
)
results = response.json()

print(f"Total: {results['summary']['total']}")
print(f"Anomalies: {results['summary']['anomalies']}")
print(f"Anomaly rate: {results['summary']['anomaly_rate']*100:.1f}%")
```

---

### JavaScript/Node.js Examples

```javascript
const axios = require('axios');

const API_URL = 'http://localhost:8000';

// Detect single log
async function detectLog(logLine) {
  try {
    const response = await axios.post(`${API_URL}/detect`, {
      log_line: logLine
    });
    
    const result = response.data;
    if (result.is_anomaly) {
      console.log(`🔴 ANOMALY: ${result.anomaly_score.toFixed(3)}`);
    } else {
      console.log(`🟢 NORMAL: ${result.anomaly_score.toFixed(3)}`);
    }
    
    return result;
  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Stream logs from file
const fs = require('fs');
const readline = require('readline');

async function streamLogs(logFile) {
  const fileStream = fs.createReadStream(logFile);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });

  for await (const line of rl) {
    if (line.trim()) {
      await detectLog(line);
    }
  }
}

// Usage
detectLog('192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] "GET / HTTP/1.1" 200 1234');
```

---

## ⚙️ Configuration

### Model Configuration

The API automatically loads model configuration from:
```
artifacts/ensemble_model_export/
├── model_config.json          # Model metadata
├── template_vocab.json        # Template vocabulary
├── transformer_model.pt       # Transformer weights
└── isolation_forest.pkl       # Isolation Forest model
```

### Warmup Configuration

Adjust warmup period based on traffic volume:

```python
# In api/server_adaptive.py
detector = AdaptiveEnsembleDetector(
    model_dir=model_dir,
    warmup_logs=50000,  # Change this
    window_size=20,
    device='cpu'
)
```

Recommendations:
- **Low traffic** (<1k/day): `warmup_logs=1000`
- **Medium traffic** (1k-100k/day): `warmup_logs=10000`
- **High traffic** (>100k/day): `warmup_logs=50000`

---

## 📊 Monitoring

### Health Check Endpoint

Use `/health` for monitoring tools (Kubernetes, Docker Compose, etc.):

```bash
# Docker health check
HEALTHCHECK --interval=30s --timeout=10s \
  CMD curl -f http://localhost:8000/health || exit 1

# Kubernetes liveness probe
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 40
  periodSeconds: 30
```

### Metrics to Monitor

1. **Phase**: Track learning progress (warmup → training → ensemble)
2. **Logs Processed**: Ensure system is processing requests
3. **Active Models**: Confirm models are activating correctly
4. **Anomaly Rate**: Monitor for unusual spikes (>30% may indicate issues)
5. **Response Time**: Should be <100ms for single log detection

### Logging

Logs are written to:
- **Container**: `/app/logs/`
- **Host**: `./logs/` (via volume mount)

View logs:
```bash
# Docker logs
docker-compose logs -f anomaly-detection-api

# Application logs
tail -f logs/api.log
```

---

## 🔒 Security Considerations

### Rate Limiting

Using Nginx (see `nginx.conf.example`):
- 10 requests/second per IP
- Burst of 20 requests allowed

### Authentication

Add API key authentication:

```python
from fastapi import Header, HTTPException

async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != os.getenv("API_KEY"):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

@app.post("/detect", dependencies=[Depends(verify_api_key)])
async def detect_single(request: LogRequest):
    # ...
```

### HTTPS

1. Obtain SSL certificate
2. Update `nginx.conf.example` HTTPS section
3. Mount certificates: `./ssl:/etc/nginx/ssl:ro`

---

## 🐛 Troubleshooting

### Issue: High memory usage

**Solution**: Reduce warmup logs or restart container
```bash
docker-compose restart
```

### Issue: Models not activating

**Solution**: Check model artifacts are mounted correctly
```bash
docker-compose exec anomaly-detection-api ls -la /app/artifacts/ensemble_model_export/
```

### Issue: Slow response times

**Solution**: 
1. Increase CPU/memory limits in `docker-compose.prod.yml`
2. Use multiple workers: `-e WORKERS=4`
3. Consider GPU support for transformer

### Issue: Parse errors

**Solution**: Ensure logs are in Apache Common or Combined format
```bash
# Valid formats:
# Common:   IP - - [timestamp] "METHOD path PROTOCOL" status size
# Combined: IP - - [timestamp] "METHOD path PROTOCOL" status size "referer" "user-agent"
```

---

## 📦 Production Deployment Checklist

- [ ] Configure environment variables (`MODEL_DIR`, `WARMUP_LOGS`)
- [ ] Set up volume mounts for model artifacts
- [ ] Configure resource limits (CPU, memory)
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Set up rate limiting via Nginx
- [ ] Configure log rotation
- [ ] Set up monitoring and alerting
- [ ] Test health check endpoint
- [ ] Document API endpoints for consumers
- [ ] Set up backup for trained models (after warmup)

---

## 📄 License

See LICENSE file in repository root.

---

## 🤝 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Contact: your-email@example.com

---

**API Version**: 2.0.0  
**Last Updated**: October 22, 2025
