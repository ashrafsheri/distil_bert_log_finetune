# Scripts Overview

## Quick Reference

| Script | Purpose | Duration | Logs Generated |
|--------|---------|----------|----------------|
| `setup_and_run.sh` | Interactive setup wizard | Varies | Varies |
| `quick_test.sh` | Quick functionality test | 1-2 min | 1,000 |
| `production_run.sh` | Full production run | 45-60 min | 100,000 |
| `log_generator.py` | Main generator script | Configurable | Configurable |
| `test_attacks.py` | Test attack detection | 1-2 min | ~30 attacks |
| `monitor.sh` | Real-time monitoring | Continuous | N/A |

## Recommended Workflow

### First Time Setup

```bash
# 1. Navigate to scripts directory
cd /root/distil_bert_log_finetune/scripts

# 2. Run the interactive setup
./setup_and_run.sh
```

The interactive setup will:
- Check prerequisites
- Install dependencies
- Verify services are running
- Let you choose what to run

### Quick Testing (Recommended First)

```bash
# Test with 1,000 logs to verify everything works
./quick_test.sh
```

**What to check after quick test:**
1. Nginx logs: `sudo tail -n 20 /var/log/nginx/access.log`
2. Fluent-bit is sending: `sudo journalctl -u fluent-bit -n 20`
3. Check metrics: `curl http://localhost:2020/api/v1/metrics`

### Production Run

Once quick test is successful:

```bash
# Generate full 100k logs
./production_run.sh
```

**Monitor progress:**
```bash
# In another terminal
./monitor.sh
```

## Script Details

### 1. setup_and_run.sh (Interactive Setup Wizard)

**Features:**
- Checks all prerequisites
- Installs dependencies
- Verifies services
- Interactive menu for all operations

**Usage:**
```bash
./setup_and_run.sh
```

**Menu Options:**
1. Quick Test (1k logs)
2. Medium Run (10k logs)
3. Production Run (100k logs)
4. Custom Configuration
5. Test Attack Patterns Only
6. Monitor Logs
7. Exit

### 2. log_generator.py (Main Generator)

**Description:** Comprehensive Python script that generates realistic web traffic including both legitimate user behavior and attack patterns.

**Key Features:**
- Simulates 3 user types: Casual Browsers (60%), Contributors (30%), Admins (10%)
- 9 different attack patterns (SQL injection, XSS, path traversal, etc.)
- Realistic timing with human-like delays
- Multiple user agents (browsers/devices)
- Session-based behavior
- Progress tracking

**Usage:**
```bash
# Basic (100k logs, 15% attacks)
python3 log_generator.py

# Custom target
python3 log_generator.py --target 10000

# Custom attack ratio
python3 log_generator.py --attack-ratio 0.30

# Different server
python3 log_generator.py --url http://192.168.1.100:5000

# Combined
python3 log_generator.py --target 50000 --attack-ratio 0.20 --url http://localhost:5000
```

**Attack Types Simulated:**
1. SQL Injection (17 different payloads)
2. XSS - Cross-Site Scripting (12 payloads)
3. Path Traversal (7 payloads)
4. Command Injection (7 payloads)
5. Brute Force enumeration
6. Malformed requests
7. Unauthorized access attempts
8. Header injection
9. DDoS simulation (burst requests)

**Legitimate Behaviors:**
- Browse GCPs (paginated)
- View GCP details
- Create/update GCPs
- Approve/reject GCPs
- Browse documents
- Create documents
- Browse API cycles
- Submit funnel data
- Submit checklists
- Get surveys
- Update survey progress

### 3. quick_test.sh

**Purpose:** Fast verification that everything is working

**What it does:**
- Generates 1,000 logs
- Takes 1-2 minutes
- Shows how to check results

**Usage:**
```bash
./quick_test.sh
```

### 4. production_run.sh

**Purpose:** Full production log generation for model training

**What it does:**
- Generates 100,000 logs
- Takes 45-60 minutes
- Logs output to file
- Shows completion summary

**Usage:**
```bash
./production_run.sh
```

**Output saved to:**
`../logs/generation_YYYYMMDD_HHMMSS.log`

### 5. test_attacks.py

**Purpose:** Test specific attack patterns to verify detection

**What it does:**
- Tests SQL injection
- Tests XSS
- Tests path traversal
- Tests brute force
- Also tests legitimate traffic for comparison

**Usage:**
```bash
python3 test_attacks.py
```

**When to use:**
- After setting up LogGuard
- To verify attack detection is working
- Before running full log generation
- To test specific attack types

### 6. monitor.sh

**Purpose:** Real-time monitoring dashboard

**What it shows:**
- Latest nginx access logs (last 5)
- Fluent-bit service status
- Fluent-bit metrics (records processed, retries, errors)
- Recent Fluent-bit issues
- Request rate (last minute)

**Usage:**
```bash
./monitor.sh
```

**Refreshes:** Every 5 seconds

**Use while:**
- Running log generation
- Debugging Fluent-bit issues
- Monitoring log flow

**Press Ctrl+C to stop**

## Performance Characteristics

### Quick Test (1,000 logs)
- **Time:** 1-2 minutes
- **Rate:** ~10-15 requests/second
- **Attack logs:** ~150
- **Legitimate logs:** ~850
- **Use case:** Testing, verification

### Medium Run (10,000 logs)
- **Time:** 10-15 minutes
- **Rate:** ~15-20 requests/second
- **Attack logs:** ~1,500
- **Legitimate logs:** ~8,500
- **Use case:** Model warmup, triggers training

### Production Run (100,000 logs)
- **Time:** 45-60 minutes
- **Rate:** ~30-40 requests/second
- **Attack logs:** ~15,000
- **Legitimate logs:** ~85,000
- **Use case:** Full model training

## Troubleshooting

### "Connection refused" errors

**Problem:** Backend API not running

**Solution:**
```bash
cd ../backend
npm install  # if first time
npm start
```

### Fluent-bit not sending logs

**Problem:** Service not running or misconfigured

**Solutions:**
```bash
# Check status
sudo systemctl status fluent-bit

# Restart service
sudo systemctl restart fluent-bit

# Check logs
sudo journalctl -u fluent-bit -n 50

# Verify configuration
cat /etc/fluent-bit/fluent-bit.conf
```

### Nginx not logging

**Problem:** Nginx not running or log rotation

**Solutions:**
```bash
# Check nginx status
sudo systemctl status nginx

# Check if log file exists
ls -lh /var/log/nginx/access.log

# Test nginx config
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx
```

### Slow generation

**Problem:** Network latency or server overload

**Solutions:**
- Reduce delays in log_generator.py (edit `human_delay()` calls)
- Check server CPU/memory usage
- Run against localhost instead of remote server
- Use smaller target number

### HTTP 500 errors

**Problem:** Server-side processing issues

**Check:**
```bash
# Backend logs
cd ../backend
npm run logs  # or check console where backend is running

# LogGuard anomaly service logs
docker logs <logguard_container>
```

## Integration Check

Before running production, verify:

1. ✅ **Backend is accessible:**
   ```bash
   curl http://localhost:5000/api/gcp?page=1&limit=1
   ```

2. ✅ **Nginx is logging:**
   ```bash
   curl http://localhost:5000/api/gcp
   sudo tail -n 5 /var/log/nginx/access.log
   ```

3. ✅ **Fluent-bit is running:**
   ```bash
   sudo systemctl status fluent-bit
   ```

4. ✅ **Fluent-bit is sending:**
   ```bash
   curl http://localhost:2020/api/v1/metrics
   ```

5. ✅ **LogGuard is receiving:**
   - Check LogGuard dashboard
   - Verify organization log count is increasing

## Example Session

```bash
# 1. Navigate to scripts
cd /root/distil_bert_log_finetune/scripts

# 2. Install dependencies (first time only)
pip3 install -r requirements.txt

# 3. Run quick test
./quick_test.sh

# 4. Monitor in separate terminal
# (Open new terminal)
cd /root/distil_bert_log_finetune/scripts
./monitor.sh

# 5. After verification, run production
./production_run.sh

# 6. Monitor LogGuard dashboard
# - Check org log count
# - Watch for model training notification
# - Verify anomaly detections
```

## Tips for Best Results

1. **Start small:** Always run quick test first
2. **Monitor continuously:** Use monitor.sh during generation
3. **Check incrementally:** Don't wait until completion to check if it's working
4. **Verify LogGuard:** Ensure logs are reaching LogGuard server
5. **Space out runs:** Give server time to process between large runs
6. **Save logs:** Production run saves output log for debugging

## Expected Timeline

| Phase | Logs | Time | What Happens |
|-------|------|------|--------------|
| Warmup | 0-10k | 0-15 min | Teacher model detects anomalies |
| Training Start | 10k | ~15 min | System begins training student model |
| Training | 10k-100k | 15-60 min | Student model training continues |
| Complete | 100k | ~60 min | Email notification sent |
| Active | 100k+ | Ongoing | Custom student model active |

## File Structure

```
scripts/
├── README.md                 # Detailed documentation
├── OVERVIEW.md              # This file - quick reference
├── requirements.txt         # Python dependencies
├── log_generator.py         # Main generator (Python)
├── setup_and_run.sh         # Interactive wizard
├── quick_test.sh            # Quick test (1k logs)
├── production_run.sh        # Full run (100k logs)
├── test_attacks.py          # Attack pattern tester
└── monitor.sh               # Real-time monitoring
```

## Support

For issues:
1. Check this OVERVIEW.md and README.md
2. Run `./setup_and_run.sh` for guided setup
3. Test with `./quick_test.sh` first
4. Monitor with `./monitor.sh`
5. Check service logs (nginx, fluent-bit, backend)

---

**Ready to start?**
```bash
./setup_and_run.sh
```
