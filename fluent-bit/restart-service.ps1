# Restart Fluent Bit Service with Updated Configuration
# Run as Administrator

param(
    [string]$ServiceName = "FluentBit",
    [string]$ConfigFile = "fluent-bit-simple.conf"
)

Write-Host "Restarting Fluent Bit service with updated configuration..." -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

# Stop the service if it's running
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping Fluent Bit service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
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
    Write-Host "Could not find Fluent Bit installation. Please ensure Fluent Bit is installed." -ForegroundColor Red
    exit 1
}

Write-Host "Fluent Bit found at: $fluentBitPath" -ForegroundColor Green

# Copy updated configuration
$configDir = Join-Path $fluentBitPath "conf"
$targetConfig = Join-Path $configDir "fluent-bit.conf"

Write-Host "Copying updated configuration..." -ForegroundColor Yellow
try {
    Copy-Item $ConfigFile -Destination $targetConfig -Force
    Write-Host "Configuration updated successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to copy configuration: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test configuration
$fluentBitExe = Join-Path $fluentBitPath "bin\fluent-bit.exe"
Write-Host "Testing configuration..." -ForegroundColor Yellow
try {
    & $fluentBitExe -c $targetConfig -D
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Configuration test passed" -ForegroundColor Green
    } else {
        Write-Host "Configuration test failed, but continuing..." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Configuration test error: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Start the service
Write-Host "Starting Fluent Bit service..." -ForegroundColor Yellow
try {
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 5
    
    $serviceStatus = Get-Service -Name $ServiceName
    if ($serviceStatus.Status -eq "Running") {
        Write-Host "Fluent Bit service started successfully!" -ForegroundColor Green
        Write-Host "Service Status: $($serviceStatus.Status)" -ForegroundColor Cyan
    } else {
        Write-Host "Service failed to start. Status: $($serviceStatus.Status)" -ForegroundColor Red
    }
} catch {
    Write-Host "Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nFluent Bit service restart completed!" -ForegroundColor Green
Write-Host "Service Name: $ServiceName" -ForegroundColor Cyan
Write-Host "Configuration: $targetConfig" -ForegroundColor Cyan
Write-Host "`nTo monitor logs:" -ForegroundColor Yellow
Write-Host "  Get-Content `"$($PWD)\fluent-bit.log`" -Wait" -ForegroundColor White
Write-Host "`nTo check service status:" -ForegroundColor Yellow
Write-Host "  Get-Service -Name $ServiceName" -ForegroundColor White
