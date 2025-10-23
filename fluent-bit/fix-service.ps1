# Fix Fluent Bit Service Script
# Run as Administrator

param(
    [string]$ServiceName = "FluentBit"
)

Write-Host "Fixing Fluent Bit Service..." -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

# Find Fluent Bit installation
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
    Write-Host "Fluent Bit not found. Please install it first." -ForegroundColor Red
    exit 1
}

Write-Host "Found Fluent Bit at: $fluentBitPath" -ForegroundColor Green

# Stop and remove existing service
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Removing existing service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName
    Start-Sleep -Seconds 2
}

# Create new service with correct path
$fluentBitExe = Join-Path $fluentBitPath "bin\fluent-bit.exe"
$configFile = Join-Path $fluentBitPath "conf\fluent-bit.conf"

Write-Host "Creating service with correct path..." -ForegroundColor Yellow
Write-Host "Executable: $fluentBitExe" -ForegroundColor Cyan
Write-Host "Config: $configFile" -ForegroundColor Cyan

# Test configuration first
Write-Host "Testing configuration..." -ForegroundColor Yellow
try {
    & $fluentBitExe -c $configFile -D
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Configuration test passed" -ForegroundColor Green
    } else {
        Write-Host "Configuration test failed, but continuing..." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Configuration test error: $($_.Exception.Message)" -ForegroundColor Yellow
}

try {
    New-Service -Name $ServiceName -BinaryPathName "`"$fluentBitExe`" -c `"$configFile`"" -DisplayName "Fluent Bit Log Shipper" -StartupType Automatic -Description "Fluent Bit log shipping service for Apache logs"
    Write-Host "Service created successfully" -ForegroundColor Green
    
    # Start the service
    Write-Host "Starting service..." -ForegroundColor Yellow
    Start-Service -Name $ServiceName
    Write-Host "Service started successfully" -ForegroundColor Green
    
    # Check status
    $status = (Get-Service -Name $ServiceName).Status
    Write-Host "Service Status: $status" -ForegroundColor Cyan
    
} catch {
    Write-Host "Failed to create service: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Trying alternative method..." -ForegroundColor Yellow
    
    # Alternative method using sc.exe
    try {
        sc.exe create $ServiceName binPath= "`"$fluentBitExe`" -c `"$configFile`"" start= auto DisplayName= "Fluent Bit Log Shipper"
        Write-Host "Service created using sc.exe" -ForegroundColor Green
        Start-Service -Name $ServiceName
    } catch {
        Write-Host "Failed to create service: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`nFluent Bit service fixed!" -ForegroundColor Green
Write-Host "Service Status: $(Get-Service -Name $ServiceName | Select-Object -ExpandProperty Status)" -ForegroundColor Cyan
