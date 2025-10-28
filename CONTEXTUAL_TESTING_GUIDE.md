# Contextual Anomaly Detection Testing Guide

## Overview

The `test_contextual_evolution.py` script demonstrates how the adaptive anomaly detection system's scores evolve across batches of logs, showing contextual awareness and progressive learning.

## Quick Start

```bash
python3 test_contextual_evolution.py
```

## What This Test Shows

### 1. **Sequence Length Progression**
- Each log in a session builds contextual awareness
- Transformer maintains a sliding window (default: 20 logs)
- Sequence tracking: 1 → 2 → 3 → 4 → ... → 20

### 2. **Pattern Recognition**
- **Normal patterns** create LOW scores (0.0 - 0.3)
- **Slight deviations** create MEDIUM scores (0.3 - 0.7)
- **Clear anomalies** create HIGH scores (0.7 - 1.0)

### 3. **Three-Model Ensemble**
- **Rule-based**: Catches known attack patterns (SQL injection, XSS, path traversal)
- **Isolation Forest**: Catches statistical outliers in request features
- **Transformer**: Catches contextual deviations and unusual sequences

## Test Scenarios

### Test 1: Normal Access Pattern
**Expected**: Scores stay low throughout
```
5 identical requests to /api/users
Result: All scores ~0.0 (normal behavior)
```

### Test 2: Anomaly in Context
**Expected**: Score spike at the anomaly
```
Log 1-2: Normal requests to /api/profile
Log 3:   SQL injection attempt → HIGH SCORE
Log 4-5: Back to normal (may be elevated)
```

### Test 3: Gradual Escalation
**Expected**: Progressive score increase
```
Log 1: Normal access          → Score: 0.0
Log 2: First 403 error        → Score: 0.1
Log 3: Multiple 403s          → Score: 0.3
Log 4: More errors            → Score: 0.5
Log 5: Path traversal attack  → Score: 1.0
```

### Test 4: Session Independence
**Expected**: Separate contexts per session
```
Session 1: Builds context from logs 1-3
Session 2: Starts fresh (seq length resets to 1)
```

## Training Status

### Before Training (< 50,000 logs)
- ✅ Rule-based detection works
- ❌ Isolation Forest not ready (scores: 0.0)
- ❌ Transformer not ready (scores: 0.0)
- Sequence length tracked but not scored

### After Training (≥ 50,000 logs)
- ✅ All three models active
- ✅ Contextual scoring enabled
- ✅ Sequence-based anomaly detection
- ✅ Full ensemble voting

## Output Format

```
Log #1: User alice accessed /api/users from 192.168.1.100...
  Timestamp: 2025-10-27T12:00:00
  IP: 192.168.1.100, Status: 200, Response: 45ms

  Overall Detection:
    Is Anomaly: False
    Anomaly Score: 0.0000
    Phase: warmup

  Model Scores:
    Rule-based: 0.0000 | Patterns: []
    Isolation Forest: Not ready
    Transformer: Not ready
```

## Evolution Summary Table

```
Log#   Seq Len    Trans Score     Anomaly Score   Anomaly
--------------------------------------------------------------
1      1          0.0000          0.0000          NO
2      2          0.0000          0.0000          NO
3      3          0.8523          0.7621          YES  ← Spike!
4      4          0.2341          0.3214          NO
5      5          0.1245          0.2103          NO
```

## Key Insights

### Contextual vs Isolated Detection

| Scenario | Sequence Length | Detection Quality |
|----------|----------------|-------------------|
| Single log | 1 | Limited - relies on rule-based |
| Few logs | 2-4 | Emerging - patterns starting |
| Rich context | 5-20 | Excellent - full contextual |

### Session Management

- Each `session_id` maintains independent context
- Typically keyed by IP address or user ID
- No cross-contamination between sessions
- Context resets when session ends

## Running Comparisons

### Before Training
```bash
# System has < 50k logs
python3 test_contextual_evolution.py > before_training.txt
```

### After Training
```bash
# Wait for system to process 50k+ logs
python3 test_contextual_evolution.py > after_training.txt

# Compare results
diff before_training.txt after_training.txt
```

## Expected Differences After Training

| Metric | Before | After |
|--------|--------|-------|
| Sequence Length | 0 | 1-20 |
| Transformer Score | 0.0 | 0.0-1.0 |
| Isolation Forest | Not ready | Active |
| Context Field | N/A | "single-log", "sequential", or "batch" |
| Anomaly Detection | Rules only | Full ensemble |

## API Endpoints Used

- `GET /anomaly/status` - Check training status
- `POST /anomaly/detect/batch` - Send batch for detection

## Log Format

The test generates nginx Combined Log Format (same as Apache Combined):
```
192.168.1.100 - - [27/Oct/2025:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 450 "-" "Mozilla/5.0"
```

This matches the default nginx combined log format:
```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

## Customization

Modify the test to create your own scenarios:

```python
# Create custom log
logs.append(create_log_entry(
    "Custom message: {user} from {ip}",
    datetime.now(),
    user="testuser",
    path="/custom/path",
    ip="10.0.0.1",
    status=200,
    response_time=100,
    method="POST"
))

# Send batch
result = send_batch(logs, session_id="custom_test")
```

## Troubleshooting

### No results returned
- Check that anomaly detection service is running: `sudo docker-compose ps`
- Verify nginx is routing correctly: `curl http://localhost/anomaly/status`

### All scores are 0.0
- Normal if transformer hasn't trained yet (need 50k logs)
- Rule-based should still catch known attack patterns

### Connection refused
- Ensure docker containers are up: `sudo docker-compose up -d`
- Check nginx configuration includes `/anomaly/` proxy

## Next Steps

1. ✅ Run test before training (baseline)
2. ⏳ Accumulate 50,000 logs through normal traffic
3. ⏳ Wait for automatic transformer training
4. ✅ Run test after training (comparison)
5. 📊 Analyze score evolution and context awareness

## Example Output Interpretation

```
Test 2: Anomaly in Context
---------------------------
Log 1-2: Score 0.00 → Building normal context
Log 3:   Score 0.95 → SQL injection detected!
Log 4-5: Score 0.15 → Returning to normal pattern
```

This shows:
- Context established with logs 1-2
- Anomaly clearly identified in log 3
- System recognizes return to normal in logs 4-5
- Contextual awareness working as expected!
