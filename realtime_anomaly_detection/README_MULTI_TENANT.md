# Multi-Tenant Log Anomaly Detection: Student-Teacher Architecture

This directory contains the implementation of a multi-tenant anomaly detection system using a student-teacher model architecture. This design enables the system to work as a SaaS service, supporting multiple projects with project-specific models.

## Architecture Overview

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                     Teacher Model                             │
                    │  (General patterns - learns from all projects)               │
                    │  - Full Transformer (4 layers, 256 dim)                       │
                    │  - Shared Isolation Forest                                    │
                    │  - Rule-based detector                                        │
                    └─────────────────────────────────────────────────────────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
        ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
        │  Student Model A  │      │  Student Model B  │      │  Student Model C  │
        │  (Project A)      │      │  (Project B)      │      │  (Project C)      │
        │  - Light Transformer     │  - Light Transformer     │  - Light Transformer
        │  - Project-specific      │  - Project-specific      │  - Project-specific
        │    vocabulary            │    vocabulary            │    vocabulary
        └───────────────────┘      └───────────────────┘      └───────────────────┘
```

## Workflow

### 1. Project Creation
- Each project gets a unique API key
- Elasticsearch index pattern is assigned: `logs-{project_id}`
- Project starts in **warmup** phase

### 2. Warmup Phase (Uses Teacher Model)
- Teacher model handles all detection during warmup
- Logs are collected and processed
- Templates are extracted and vocabulary built
- Training sequences are accumulated
- Default: 10,000 logs (configurable up to 50,000+)

### 3. Student Training
- Triggered automatically when warmup threshold reached
- Knowledge distillation from teacher model
- Combined loss: hard labels + soft labels from teacher
- Student model: smaller architecture (2 layers, 128 dim)
- Fast training (5 epochs, ~1-2 minutes)

### 4. Active Phase (Uses Student Model)
- Project-specific student model handles detection
- Better accuracy for project-specific patterns
- Lower latency (smaller model)
- Continues collecting data for teacher updates

### 5. Periodic Teacher Updates
- Weekly (configurable) updates from student logs
- Aggregates patterns from all active projects
- Improves generalization capability
- Knowledge flows: Students → Teacher → New Students

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API information |
| GET | `/health` | Health check |
| POST | `/projects` | Create new project |
| GET | `/projects` | List all projects (admin) |

### Authenticated Endpoints (Require X-API-Key header)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/detect` | Detect anomaly in single log |
| POST | `/detect/batch` | Detect anomalies in batch |
| GET | `/project/status` | Get project status |
| POST | `/project/reset-sessions` | Reset session history |

### Admin Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/teacher` | Teacher model info |
| POST | `/admin/teacher/update` | Force teacher update |
| GET | `/admin/update-history` | Update history |

## Quick Start

### 1. Start the Server

```bash
# Using the startup script
./api/start_multi_tenant.sh

# Or with Docker
docker build -f Dockerfile.multi_tenant -t anomaly-detector-mt .
docker run -p 8000:8000 -v ./artifacts:/app/artifacts anomaly-detector-mt
```

### 2. Create a Project

```bash
curl -X POST http://localhost:8000/projects \
  -H "Content-Type: application/json" \
  -d '{
    "project_name": "My Web App",
    "warmup_threshold": 10000
  }'
```

Response:
```json
{
  "project_id": "abc123...",
  "project_name": "My Web App",
  "api_key": "sk-xxxxxxxxxxxxx",
  "warmup_threshold": 10000,
  "es_index_pattern": "logs-abc123..."
}
```

**⚠️ Save the API key! It's only shown once.**

### 3. Send Logs for Detection

```bash
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk-xxxxxxxxxxxxx" \
  -d '{
    "log_line": "192.168.1.1 - - [22/Oct/2025:10:30:45 +0000] \"GET /api/users HTTP/1.1\" 200 1234"
  }'
```

Response:
```json
{
  "is_anomaly": false,
  "anomaly_score": 0.15,
  "model_type": "teacher",
  "phase": "warmup",
  "project_id": "abc123...",
  "log_count": 1,
  "warmup_progress": 0.01,
  ...
}
```

### 4. Monitor Progress

```bash
curl http://localhost:8000/project/status \
  -H "X-API-Key: sk-xxxxxxxxxxxxx"
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_DIR` | `/app/artifacts/ensemble_model_export` | Base model directory |
| `STORAGE_DIR` | `/app/data/multi_tenant` | Data storage directory |
| `HOST` | `0.0.0.0` | API host |
| `PORT` | `8000` | API port |
| `DEVICE` | `cpu` | PyTorch device (cpu/cuda) |
| `WARMUP_THRESHOLD` | `10000` | Default logs before training |
| `TEACHER_UPDATE_DAYS` | `7` | Days between teacher updates |

## File Structure

```
realtime_anomaly_detection/
├── api/
│   ├── server_multi_tenant.py    # Multi-tenant API server
│   ├── start_multi_tenant.sh     # Startup script
│   ├── server.py                 # Original single-tenant server
│   └── server_adaptive.py        # Adaptive single-tenant server
├── models/
│   ├── project_manager.py        # Project/API key management
│   ├── teacher_model.py          # Teacher model class
│   ├── student_model.py          # Student model class
│   ├── multi_tenant_detector.py  # Main orchestrator
│   ├── knowledge_distillation.py # Training utilities
│   ├── ensemble_detector.py      # Original ensemble detector
│   └── adaptive_detector.py      # Original adaptive detector
├── streaming/
│   └── log_streamer.py           # Log streaming utility
├── Dockerfile.multi_tenant       # Multi-tenant Docker image
└── requirements.txt              # Python dependencies
```

## Model Sizes

| Component | Teacher | Student |
|-----------|---------|---------|
| Transformer Layers | 4 | 2 |
| Hidden Dimension | 256 | 128 |
| FFN Dimension | 1024 | 512 |
| Attention Heads | 8 | 4 |
| Approx. Parameters | 17M | 4M |

## Knowledge Distillation

The student models are trained using a combination of:

1. **Hard Labels**: Standard cross-entropy with actual next-token targets
2. **Soft Labels**: KL divergence with teacher's probability distributions

Loss function:
```
L = (1 - α) × L_hard + α × L_soft
```

Where:
- `α = 0.5` (distillation weight)
- `T = 3.0` (temperature for softening distributions)

## Elasticsearch Integration

Each project has an associated index pattern for storing logs:

```
logs-{project_id}
```

This enables:
- Project-isolated log storage
- Per-project search and analysis
- Compliance with data isolation requirements

## Monitoring

### Health Check

```bash
curl http://localhost:8000/health
```

Returns:
```json
{
  "status": "healthy",
  "teacher_loaded": true,
  "total_projects": 3,
  "active_student_models": 2,
  "training_in_progress": 0
}
```

### Project Status

Track warmup progress and model status per project:

```bash
curl -H "X-API-Key: sk-xxx" http://localhost:8000/project/status
```

## Best Practices

1. **Warmup Threshold**: Start with 10,000 logs. Increase for projects with high log variety.

2. **API Key Security**: Store API keys securely. They cannot be retrieved after creation.

3. **Session IDs**: Use consistent session IDs (e.g., IP address) for better sequence modeling.

4. **Batch Processing**: Use `/detect/batch` for bulk log processing (more efficient).

5. **Teacher Updates**: Let the automatic weekly update run. Force updates only when necessary.

## Troubleshooting

### Student Model Not Training

Check that:
- Warmup threshold has been reached
- Enough training sequences collected (min 100)
- No training already in progress

### High False Positive Rate

Consider:
- Increasing warmup threshold (more diverse training data)
- Adjusting ensemble weights
- Checking for log format inconsistencies

### Memory Issues

For large deployments:
- Use GPU acceleration (`DEVICE=cuda`)
- Limit number of concurrent projects
- Increase swap space
