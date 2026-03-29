# Project Server: Fluent-bit Integration Guide

This guide walks you through setting up Fluent-bit on your project server to send logs to LogGuard.

## Prerequisites
- API key from the main LogGuard server (generated during org creation)
- The LogGuard server's public hostname/IP and port
- Root or sudo access on the project server
- Fluent-bit 2.0+ installed or ready to install

## Step 1: Get Your Configuration

From the main LogGuard server's Admin Dashboard:
1. Create a new organization (if not done already)
2. Copy the **Fluent-bit Configuration** from the org creation result
3. Note the API key and LogGuard host/port

The config will look like:
```ini
[OUTPUT]
    Name              http
    Match             *
    Host              <logguard_host>
    Port              <logguard_port>
    URI               /api/v1/logs/agent/send-logs
    Format            json
    Retry_Limit       5
    Header            X-API-Key <your_api_key>
```

## Step 2: Install Fluent-bit

### On Linux (Ubuntu/Debian)
```bash
curl https://fluent-bit.io/releases/oss/fluent-bit-2.1.0-distro.linux-amd64.tar.gz -o fluent-bit.tar.gz
tar -xzf fluent-bit.tar.gz
sudo mv fluent-bit /opt/fluent-bit
```

### On Linux (RHEL/CentOS/Fedora)
```bash
sudo dnf install fluent-bit
```

### On macOS (for testing)
```bash
brew install fluent-bit
```

### Using Docker
```bash
docker pull fluent/fluent-bit:latest
```

## Step 3: Configure Fluent-bit

### Option A: For Apache/Nginx logs

1. **Create/edit** `/etc/fluent-bit/fluent-bit.conf` or `/opt/fluent-bit/etc/fluent-bit.conf`

```ini
[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info

[INPUT]
    Name              tail
    Path              /var/log/apache2/access.log
    Parser            apache2
    Tag               apache.*
    Refresh_Interval  5
    Mem_Buf_Limit     50MB

[PARSER]
    Name              apache2
    Format            regex
    Regex             ^(?<remote>[^ ]*) (?<host>[^ ]*) (?<user>[^ ]*) \[(?<time>[^\]]*)\] "(?<method>\S+)(?: +(?<path>[^\"]*?)(?: +\S*)?)?" (?<code>[^ ]*) (?<size>[^ ]*)(?: "(?<referer>[^\"]*)" "(?<agent>[^\"]*)")?$
    Time_Key          time
    Time_Format       %d/%b/%Y:%H:%M:%S %z

[OUTPUT]
    Name              http
    Match             apache.*
    Host              <logguard_host>
    Port              <logguard_port>
    URI               /api/v1/logs/agent/send-logs
    Format            json
    Retry_Limit       5
    Header            X-API-Key <your_api_key>
```

### Option B: For generic syslog

```ini
[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info

[INPUT]
    Name              syslog
    Listen            0.0.0.0
    Port              5140
    Parser            syslog
    Tag               syslog.*

[PARSER]
    Name              syslog
    Format            regex
    Regex             ^\<(?<pri>[0-9]+)\>(?<time>[^ ]* {1,2}[^ ]* [^ ]*) (?<host>[^ ]*) (?<ident>.*?)(?:\[(?<pid>[0-9]+)\])?(?:[^\:]*\:)? *(?<message>.*)$
    Time_Key          time
    Time_Format       %b %d %H:%M:%S

[OUTPUT]
    Name              http
    Match             syslog.*
    Host              <logguard_host>
    Port              <logguard_port>
    URI               /api/v1/logs/agent/send-logs
    Format            json
    Retry_Limit       5
    Header            X-API-Key <your_api_key>
```

Replace `<logguard_host>`, `<logguard_port>`, and `<your_api_key>` with actual values.

## Step 4: Start Fluent-bit

### Standalone
```bash
/opt/fluent-bit/bin/fluent-bit -c /path/to/fluent-bit.conf
```

### As a service (systemd)
```bash
sudo systemctl start fluent-bit
sudo systemctl status fluent-bit
sudo systemctl enable fluent-bit  # Auto-start on reboot
```

### With Docker
```bash
docker run -d \
  --name fluent-bit \
  -v /path/to/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf \
  -v /var/log:/var/log:ro \
  fluent/fluent-bit:latest
```

## Step 5: Verify Logs Are Flowing

### Check Fluent-bit status
```bash
# Check if process is running
ps aux | grep fluent-bit

# Check logs (if running as service)
sudo journalctl -u fluent-bit -f
```

### Check on LogGuard main server
1. Go to Admin Dashboard
2. Find your organization
3. Verify log count increases over time
4. Check the model status badge (should show warmup progress)

## Step 6: Monitor Model Training

- **Warmup phase** (0-10k logs): Teacher model is used for detection
- **Training phase** (at 10k logs): System starts training a custom student model
- **Active phase** (when ready): Your org uses the trained student model

You'll receive an email notification when your student model is ready!

## Troubleshooting

### Logs not appearing in LogGuard?
1. Check Fluent-bit is running: `ps aux | grep fluent-bit`
2. Verify API key is correct in the config
3. Test connectivity: `curl -v http://<logguard_host>:<logguard_port>/api/v1/logs/agent/send-logs -H "X-API-Key: <api_key>" -d '[]'`
4. Check firewall: Ensure port is open from project server to LogGuard server
5. Review Fluent-bit logs for errors: `sudo journalctl -u fluent-bit -n 50`

### High CPU/Memory usage?
- Reduce `Mem_Buf_Limit` in the INPUT section
- Increase `Refresh_Interval` to reduce polling frequency
- Reduce log file size if possible

### Connection timeouts?
- Verify LogGuard host/port are reachable: `nc -zv <logguard_host> <logguard_port>`
- Check network connectivity and firewall rules
- Increase `Retry_Limit` in OUTPUT section

## Support
For issues or questions, refer to:
- Fluent-bit docs: https://docs.fluentbit.io/
- LogGuard logs: Check backend/anomaly service logs on main server
