# Log Generator Scripts

This directory contains scripts for generating realistic web traffic logs for the Nexus MXP application, including both legitimate user behavior and attack patterns for training anomaly detection models.

## Files

- `log_generator.py` - Main script that generates comprehensive web traffic logs
- `requirements.txt` - Python dependencies
- `quick_test.sh` - Quick test script to generate a small batch of logs
- `production_run.sh` - Production script to generate 100k logs

## Features

The log generator simulates:

### Legitimate User Behaviors (85% of traffic)
- **Casual Browsers**: Users browsing GCPs, documents, and API cycles
- **Contributors**: Active users creating content, submitting checklists, and funnel data
- **Administrators**: Managing GCPs, approving/rejecting submissions

### Attack Patterns (15% of traffic)
- **SQL Injection**: Various SQL injection payloads in parameters and body
- **XSS (Cross-Site Scripting)**: Script injection attempts in form fields
- **Path Traversal**: Attempts to access unauthorized files
- **Command Injection**: OS command injection attempts
- **Brute Force**: Resource enumeration and ID guessing
- **Malformed Requests**: Invalid data structures and types
- **Unauthorized Access**: Attempts to access protected endpoints
- **Header Injection**: Malicious HTTP header manipulation
- **DDoS Simulation**: Rapid repeated requests

## Installation

```bash
cd scripts
pip install -r requirements.txt
```

Or using a virtual environment (recommended):

```bash
cd scripts
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### Basic Usage

Generate 100,000 logs (default):
```bash
python3 log_generator.py
```

### Custom Configuration

Generate 10,000 logs for testing:
```bash
python3 log_generator.py --target 10000
```

Point to a different server:
```bash
python3 log_generator.py --url http://57.128.223.176
```

Increase attack ratio to 30%:
```bash
python3 log_generator.py --attack-ratio 0.30
```

Combined options:
```bash
python3 log_generator.py --url http://localhost:5000 --target 50000 --attack-ratio 0.20
```

### Quick Scripts

For testing (1,000 logs):
```bash
bash quick_test.sh
```

For production (100,000 logs):
```bash
bash production_run.sh
```

## Command Line Options

- `--url` - Base URL of the API (default: http://localhost:5000)
- `--target` - Number of requests to generate (default: 100000)
- `--attack-ratio` - Ratio of attack traffic, 0.0-1.0 (default: 0.15 = 15%)

## How It Works

### Traffic Patterns

The generator simulates realistic user sessions with:
- Random delays between requests (0.1-5 seconds, mimicking human reading/thinking time)
- Varied User-Agent strings (different browsers and devices)
- Realistic HTTP headers (Accept, Referer, Origin, etc.)
- Session-based behavior (users perform multiple related actions)
- Natural flow (browsing → viewing details → creating content)

### Attack Simulation

Attacks are distributed throughout normal traffic to simulate real-world scenarios:
- Attacks come in bursts (attack sessions)
- Multiple attack vectors per session
- Mix of sophisticated and simple attacks
- Varying intensity and patterns

### API Coverage

The script interacts with all major endpoints:
- `/api/gcp` - Global Community Projects
- `/api/documents` - Document management
- `/api/api-cycles` - API cycles
- `/api/mxfunnel` - MX funnel metrics
- `/api/checklist` - MX checklists
- `/api/survey` - Surveys
- `/api/route-permissions` - Route permissions

## Output

The script provides real-time progress updates:
```
Starting log generation...
Target: 100000 requests
Attack ratio: 15.0%
Base URL: http://localhost:5000

Progress: 100/100000 requests (15 attacks, 15.0%)
Progress: 200/100000 requests (28 attacks, 14.0%)
...
```

Final summary:
```
============================================================
Log generation complete!
Total requests: 100000
Attack requests: 15234 (15.2%)
Legitimate requests: 84766
Time elapsed: 2847.3 seconds (47.5 minutes)
Average rate: 35.1 requests/second
============================================================
```

## Integration with Fluent-bit

The logs generated will be automatically captured by:
1. **Nginx** - HTTP access logs in `/var/log/nginx/access.log`
2. **Fluent-bit** - Monitoring nginx logs and sending to LogGuard
3. **LogGuard** - Processing logs through the anomaly detection pipeline

Make sure:
- Nginx is running and logging access requests
- Fluent-bit service is active and configured
- LogGuard server is accessible and processing logs

## Performance Considerations

- **Rate Limiting**: The script includes human-like delays to avoid overwhelming the server
- **Memory**: Minimal memory footprint, suitable for long-running sessions
- **Network**: Approximately 35-50 requests/second depending on delays
- **Duration**: 100k logs takes ~45-60 minutes to generate with realistic timing

## Troubleshooting

**Connection refused errors**:
```bash
# Make sure the backend server is running
cd backend
npm start
```

**Slow generation**:
```bash
# Reduce delays for faster generation (less realistic)
# Edit log_generator.py and reduce sleep times in human_delay()
```

**Monitor in real-time**:
```bash
# Watch nginx access logs
sudo tail -f /var/log/nginx/access.log

# Watch Fluent-bit logs
sudo journalctl -u fluent-bit -f

# Check Fluent-bit metrics
curl http://localhost:2020/api/v1/metrics
```

## License

Part of the Nexus MXP project.
