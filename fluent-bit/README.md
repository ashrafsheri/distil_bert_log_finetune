# Fluent Bit Log Shipper

Production-ready log shipping solution using Fluent Bit to monitor Apache access logs and send them to the backend API.

## 🚀 **Quick Start**

### **Prerequisites**
1. **Backend must be running** on `http://localhost:8000`
2. **Apache log file** must exist at the configured path
3. **Administrator privileges** required for installation

### **Installation (Windows)**
```powershell
# Run PowerShell as Administrator
cd C:\Users\hp\Documents\GitHub\distil_bert_log_finetune\fluent-bit
.\install.ps1
```

The script will:
- ✅ Install Chocolatey (if not present)
- ✅ Install Fluent Bit via Chocolatey
- ✅ Copy configuration files
- ✅ Create Windows service
- ✅ Start the service automatically

## 📁 **Configuration**

### **Apache Log Path**
Currently configured for:
```
C:\Users\hp\Downloads\httpd-2.4.65-250724-Win64-VS17\Apache24\logs\juicebox_access.log
```

### **Backend API**
Sends logs to:
```
http://localhost:8000/api/v1/agent/sendLogs
```

### **Position Tracking**
Fluent Bit automatically tracks file position in:
```
C:\Users\hp\Documents\GitHub\distil_bert_log_finetune\fluent-bit\fluent-bit-state.db
```

## 🔧 **Service Management**

### **Check Status**
```powershell
Get-Service -Name FluentBit
```

### **Start/Stop Service**
```powershell
Start-Service -Name FluentBit
Stop-Service -Name FluentBit
Restart-Service -Name FluentBit
```

### **View Logs**
```powershell
Get-EventLog -LogName Application -Source FluentBit -Newest 10
```

## 📊 **How It Works**

1. **Fluent Bit** monitors the Apache log file
2. **Reads new log entries** every 5 seconds
3. **Parses Apache logs** (combined format)
4. **Sends to backend** via HTTP POST
5. **Tracks position** in database (survives restarts)
6. **Retries failed requests** automatically

## 🐛 **Troubleshooting**

### **Service Not Starting**
```powershell
# Check service status
Get-Service -Name FluentBit

# Check Windows Event Log
Get-EventLog -LogName Application -Source FluentBit -Newest 5
```

### **No Logs Being Sent**
1. **Check Apache log file exists** and has content
2. **Verify backend is running** on port 8000
3. **Check Fluent Bit configuration** in `fluent-bit.conf`
4. **Test backend API** manually:
   ```bash
   curl http://localhost:8000/health
   ```

### **Configuration Issues**
- **Edit config**: `C:\ProgramData\chocolatey\lib\fluent-bit\tools\conf\fluent-bit.conf`
- **Restart service** after changes: `Restart-Service -Name FluentBit`

## 🔄 **Uninstallation**

```powershell
# Stop and remove service
Stop-Service -Name FluentBit
sc.exe delete FluentBit

# Uninstall Fluent Bit
choco uninstall fluent-bit -y

# Remove configuration files
Remove-Item "C:\ProgramData\chocolatey\lib\fluent-bit" -Recurse -Force
```

## 📈 **Benefits over LogShipperAgent**

- ✅ **Production-tested** log shipper
- ✅ **Built-in position tracking** (no custom files)
- ✅ **Native retry and buffering**
- ✅ **Better performance** and reliability
- ✅ **Industry standard** solution
- ✅ **Automatic updates** via Chocolatey
- ✅ **Windows service** integration

## 🔧 **Customization**

### **Change Log File Path**
Edit `fluent-bit.conf`:
```ini
[INPUT]
    Name              tail
    Path              C:\path\to\your\apache\logs\access.log
    # ... rest of config
```

### **Change Backend URL**
Edit `fluent-bit.conf`:
```ini
[OUTPUT]
    Name              http
    Host              your-backend-host
    Port              8000
    # ... rest of config
```

### **Adjust Polling Interval**
Edit `fluent-bit.conf`:
```ini
[INPUT]
    Refresh_Interval  10  # Change from 5 to 10 seconds
    # ... rest of config
```

## 📞 **Support**

For issues:
1. Check Windows Event Log
2. Verify configuration files
3. Test backend connectivity
4. Check Apache log file permissions
