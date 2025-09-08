# smartmeter-api-test.ps1
# Run: Open PowerShell and:  .\smartmeter-api-test.ps1

$ErrorActionPreference = 'Stop'

# Adjust base URL if needed
$BaseUrl = 'http://localhost:3000'

# Helper to pretty-print JSON
function Pretty($obj) { $obj | ConvertTo-Json -Depth 10 }

Write-Host "Base URL: $BaseUrl`n"

$ApiKey = $null
$JwtToken = $null
$MeterId = $null

# 1. Health check
Write-Host "1) Health check..."
try {
    $resp = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get -ContentType "application/json" -ErrorAction Stop
    Write-Host "Health response:" (Pretty $resp)
} catch {
    Write-Warning "Health check failed: $($_.Exception.Message)"
}

# 2. Register device
Write-Host "`n2) Register device..."
$regBody = @{
    meter_make = "ESP32_SECURE"
    meter_no   = "ESP32_001_TEST"
    g32        = "G32_CONFIG_A"
    mf         = 1.0
    location   = "Building A - Test Lab"
} | ConvertTo-Json

try {
    $register = Invoke-RestMethod -Uri "$BaseUrl/auth/register-device" -Method Post -Body $regBody -ContentType "application/json" -ErrorAction Stop
    Write-Host "Register response:" (Pretty $register)
    if ($register.api_key) { $ApiKey = $register.api_key }
    if ($register.meter_id) { $MeterId = $register.meter_id }
} catch {
    Write-Warning "Register failed: $($_.Exception.Message)"
    $ApiKey = "fallback_api_key"
    $MeterId = 1
}
Write-Host "API Key: $($ApiKey -replace '^(.{20}).+$','$1...')"
Write-Host "Meter ID: $MeterId"

# 3. Admin login -> JWT
Write-Host "`n3) Admin login..."
$loginBody = @{ username="admin"; password="admin123" } | ConvertTo-Json
try {
    $login = Invoke-RestMethod -Uri "$BaseUrl/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -ErrorAction Stop
    Write-Host "Login response:" (Pretty $login)
    $JwtToken = $login.token
    if ($JwtToken) { Write-Host "Got JWT token (first 40 chars): $($JwtToken.Substring(0,[Math]::Min(40,$JwtToken.Length)))..." }
} catch {
    Write-Warning "Login failed: $($_.Exception.Message)"
}

# 4. Get device info (using API key)
Write-Host "`n4) Get device info..."
try {
    $headers = @{}
    if ($ApiKey) { $headers['X-API-Key'] = $ApiKey }
    $headers['X-Device-ID'] = 'ESP32_001_TEST'
    $device = Invoke-RestMethod -Uri "$BaseUrl/meter/$MeterId" -Method Get -Headers $headers -ErrorAction Stop
    Write-Host "Device info:" (Pretty $device)
} catch {
    Write-Warning "Device info failed: $($_.Exception.Message)"
}

# 5. Submit single meter reading
Write-Host "`n5) Submit single reading..."
$ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
$reading = @{
    reading_datetime = $ts
    r_phase_current = 25.5
    y_phase_current = 24.8
    b_phase_current = 26.2
    r_phase_voltage = 230.5
    y_phase_voltage = 231.2
    b_phase_voltage = 229.8
    kw_import = 15.2
    kw_export = 0.0
    kva_import = 18.5
    kwh_import = 1250.75
    kvah_import = 1520.25
} | ConvertTo-Json

try {
    $headers = @{ 'X-API-Key' = $ApiKey; 'X-Device-ID' = 'ESP32_001_TEST' }
    $r = Invoke-RestMethod -Uri "$BaseUrl/meter/$MeterId/reading" -Method Post -Headers $headers -Body $reading -ContentType "application/json" -ErrorAction Stop
    Write-Host "Reading submit response:" (Pretty $r)
} catch {
    Write-Warning "Submit reading failed: $($_.Exception.Message)"
}

Write-Host "`nDone."
