# Fluent Bit Installation Script for Windows using Chocolatey
# Run as Administrator

param(
    [string]$ServiceName = "FluentBit"
)

Write-Host "Installing Fluent Bit for Windows using Chocolatey..." -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

# Check if Fluent Bit is already installed and running
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    $serviceStatus = (Get-Service -Name $ServiceName).Status
    if ($serviceStatus -eq "Running") {
        Write-Host "Fluent Bit service is already installed and running!" -ForegroundColor Green
        Write-Host "Service Status: $serviceStatus" -ForegroundColor Cyan
        Write-Host "To reinstall, first run: Stop-Service -Name $ServiceName; sc.exe delete $ServiceName" -ForegroundColor Yellow
        exit 0
    } else {
        Write-Host "Fluent Bit service exists but is not running (Status: $serviceStatus)" -ForegroundColor Yellow
        Write-Host "Attempting to fix the service..." -ForegroundColor Yellow
    }
}

# Install Chocolatey if not present
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey package manager..." -ForegroundColor Yellow
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Host "Chocolatey installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "Failed to install Chocolatey: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Chocolatey is already installed" -ForegroundColor Green
}

# Install Fluent Bit via Chocolatey
Write-Host "Installing Fluent Bit via Chocolatey..." -ForegroundColor Yellow
try {
    choco install fluent-bit -y --force
    Write-Host "Fluent Bit installed successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to install Fluent Bit: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Find Fluent Bit installation path
$possiblePaths = @(
    "C:\Program Files\fluent-bit",
    "C:\Program Files\Fluent Bit", 
    "C:\ProgramData\chocolatey\lib\fluent-bit\tools"
)

$fluentBitPath = $null
foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $fluentBitExe = Join-Path $path "bin\fluent-bit.exe"
        if (Test-Path $fluentBitExe) {
            $fluentBitPath = $path
            break
        }
    }
}

if (!$fluentBitPath) {
    Write-Host "Could not find Fluent Bit installation. Searching system..." -ForegroundColor Yellow
    $foundExe = Get-ChildItem "C:\" -Recurse -Name "fluent-bit.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($foundExe) {
        $fluentBitPath = Split-Path (Split-Path "C:\$foundExe")
        Write-Host "Found Fluent Bit at: $fluentBitPath" -ForegroundColor Green
    } else {
        Write-Host "Fluent Bit executable not found. Please reinstall Fluent Bit." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Fluent Bit found at: $fluentBitPath" -ForegroundColor Green
}

# Create conf directory if it doesn't exist
$configDir = Join-Path $fluentBitPath "conf"
if (!(Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force
    Write-Host "Created config directory: $configDir" -ForegroundColor Yellow
}

# Copy configuration files
Write-Host "Copying configuration files..." -ForegroundColor Yellow
try {
    # Use simplified config for better service compatibility
    Copy-Item "fluent-bit-simple.conf" -Destination (Join-Path $configDir "fluent-bit.conf") -Force
    Write-Host "Configuration files copied successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to copy configuration files: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test configuration before creating service
$fluentBitExe = Join-Path $fluentBitPath "bin\fluent-bit.exe"
$configFile = Join-Path $configDir "fluent-bit.conf"

Write-Host "Testing Fluent Bit configuration..." -ForegroundColor Yellow
try {
    # Test configuration syntax (Fluent Bit 4.x uses -D for dry run)
    & $fluentBitExe -c $configFile -D
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Configuration test passed" -ForegroundColor Green
    } else {
        Write-Host "Configuration test failed" -ForegroundColor Red
        Write-Host "Please check the configuration file: $configFile" -ForegroundColor Yellow
        Write-Host "Trying to continue anyway..." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Failed to test configuration: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Continuing with service creation..." -ForegroundColor Yellow
}

# Create Windows Service
Write-Host "Creating Windows Service..." -ForegroundColor Yellow
try {
    # Remove existing service if it exists
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "Stopping and removing existing service..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName
        Start-Sleep -Seconds 3
    }
    
    # Create new service
    New-Service -Name $ServiceName -BinaryPathName "`"$fluentBitExe`" -c `"$configFile`"" -DisplayName "Fluent Bit Log Shipper" -StartupType Automatic -Description "Fluent Bit log shipping service for Apache logs"
    
    Write-Host "Service created successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to create service: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Trying alternative method..." -ForegroundColor Yellow
    
    # Alternative method using sc.exe
    try {
        sc.exe create $ServiceName binPath= "`"$fluentBitExe`" -c `"$configFile`"" start= auto DisplayName= "Fluent Bit Log Shipper"
        Write-Host "Service created using sc.exe" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create service with sc.exe: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Start the service
Write-Host "Starting Fluent Bit service..." -ForegroundColor Yellow
try {
    Start-Service -Name $ServiceName
    Write-Host "Service started successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "You may need to start it manually: Start-Service -Name $ServiceName" -ForegroundColor Yellow
}

Write-Host "`nFluent Bit installation completed!" -ForegroundColor Green
Write-Host "Service Name: $ServiceName" -ForegroundColor Cyan
Write-Host "Installation Path: $fluentBitPath" -ForegroundColor Cyan
Write-Host "Configuration: $configFile" -ForegroundColor Cyan
Write-Host "`nTo manage the service:" -ForegroundColor Yellow
Write-Host "  Start:   Start-Service -Name $ServiceName" -ForegroundColor White
Write-Host "  Stop:    Stop-Service -Name $ServiceName" -ForegroundColor White
Write-Host "  Status:  Get-Service -Name $ServiceName" -ForegroundColor White
Write-Host "  Logs:    Get-EventLog -LogName Application -Source FluentBit" -ForegroundColor White
Write-Host "`nFluent Bit is now monitoring your Apache logs and sending them to the backend!" -ForegroundColor Green

