@echo off
REM ======================================================================
REM Smart Meter API Test Suite - DOS Batch File
REM ======================================================================

setlocal enabledelayedexpansion

REM Configuration
set BASE_URL=http://localhost:3000
set API_KEY=ESP32_18_1757319009493_1b2aad987f9460d3
set METER_ID=18
set JWT_TOKEN=

REM Create temp directory for responses
if not exist "test_results" mkdir test_results

echo ======================================================================
echo Starting Smart Meter API Test Suite
echo ======================================================================
echo Base URL: %BASE_URL%
echo Meter ID: %METER_ID%
echo API Key: %API_KEY%
echo ======================================================================
echo.

REM Colors for output (Windows 10+)
REM Green = Success, Red = Error, Yellow = Warning
for /f %%A in ('"prompt $H &echo on &for %%B in (1) do rem"') do set BS=%%A

call :color_echo 0A "Starting API Tests..."
echo.

REM ======================================================================
REM TEST 1: Health Check
REM ======================================================================
call :test_header "1. Health Check"
curl -X GET %BASE_URL%/health -o test_results\health_check.json -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" -s
call :check_result
echo.

REM ======================================================================
REM TEST 2: Device Registration (Optional - might already exist)
REM ======================================================================
call :test_header "2. Device Registration"
curl -X POST %BASE_URL%/api/v1/auth/register-device ^
  -H "Content-Type: application/json" ^
  -d "{\"meter_make\":\"Schneider Electric\",\"meter_no\":\"SE001234567\",\"g32\":\"G32_CONFIG_A\",\"mf\":1.0,\"location\":\"Building A - Floor 1 - Room 101\"}" ^
  -o test_results\device_registration.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 3: Admin Login
REM ======================================================================
call :test_header "3. Admin Login"
curl -X POST %BASE_URL%/api/v1/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin\",\"password\":\"admin123\"}" ^
  -o test_results\admin_login.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result

REM Extract JWT token for later use
for /f "tokens=*" %%i in ('type test_results\admin_login.json ^| findstr /C:"token"') do (
    set token_line=%%i
    REM Simple token extraction - you might need to adjust this
    echo JWT token extracted for admin operations
)
echo.

REM ======================================================================
REM TEST 4: Get Device Information
REM ======================================================================
call :test_header "4. Get Device Information"
curl -X GET %BASE_URL%/api/v1/meter/%METER_ID% ^
  -H "X-API-Key: %API_KEY%" ^
  -o test_results\device_info.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 5: Get Device Configuration
REM ======================================================================
call :test_header "5. Get Device Configuration"
curl -X GET %BASE_URL%/api/v1/meter/%METER_ID%/config ^
  -H "X-API-Key: %API_KEY%" ^
  -o test_results\device_config.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 6: Submit Single Reading
REM ======================================================================
call :test_header "6. Submit Single Reading"
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/reading ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"reading_datetime\":\"2025-09-08T10:35:00Z\",\"r_phase_current\":12.5,\"y_phase_current\":11.8,\"b_phase_current\":13.2,\"r_phase_voltage\":230.5,\"y_phase_voltage\":229.8,\"b_phase_voltage\":231.2,\"kw_import\":8.5,\"kw_export\":0.0,\"kva_import\":9.2,\"kva_export\":0.0,\"kwh_import\":12450.5,\"kwh_export\":125.2,\"kvah_import\":13200.8,\"kvah_export\":145.5}" ^
  -o test_results\single_reading.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 7: Submit Batch Readings
REM ======================================================================
call :test_header "7. Submit Batch Readings"
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/readings/batch ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"readings\":[{\"reading_datetime\":\"2025-09-08T10:30:00Z\",\"r_phase_current\":12.1,\"y_phase_current\":11.5,\"b_phase_current\":12.8,\"r_phase_voltage\":230.2,\"y_phase_voltage\":229.5,\"b_phase_voltage\":230.8,\"kw_import\":8.2,\"kwh_import\":12448.3},{\"reading_datetime\":\"2025-09-08T10:35:00Z\",\"r_phase_current\":12.5,\"y_phase_current\":11.8,\"b_phase_current\":13.2,\"r_phase_voltage\":230.5,\"y_phase_voltage\":229.8,\"b_phase_voltage\":231.2,\"kw_import\":8.5,\"kwh_import\":12450.5}]}" ^
  -o test_results\batch_readings.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 8: Submit TOD Readings
REM ======================================================================
call :test_header "8. Submit TOD Readings"
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/tod-readings ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"tod_readings\":[{\"tod_period\":1,\"reading_datetime\":\"2025-09-08T10:30:00Z\",\"kwh_import\":1250.5,\"kwh_export\":15.2,\"kvah_import\":1320.8,\"kvah_export\":18.5},{\"tod_period\":2,\"reading_datetime\":\"2025-09-08T10:30:00Z\",\"kwh_import\":2100.3,\"kwh_export\":25.8,\"kvah_import\":2250.4,\"kvah_export\":28.2}]}" ^
  -o test_results\tod_readings.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 9: Device Heartbeat
REM ======================================================================
call :test_header "9. Device Heartbeat"
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/heartbeat ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"firmware_version\":\"1.2.3\",\"battery_level\":85,\"signal_strength\":-45,\"uptime\":3600,\"free_heap\":45000,\"wifi_rssi\":-55,\"temperature\":35.5,\"error_count\":0,\"last_restart_reason\":\"POWER_ON\"}" ^
  -o test_results\heartbeat.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 10: Get Latest Readings
REM ======================================================================
call :test_header "10. Get Latest Readings"
curl -X GET "%BASE_URL%/api/v1/meter/%METER_ID%/readings/latest?limit=5" ^
  -H "X-API-Key: %API_KEY%" ^
  -o test_results\latest_readings.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 11: List All Devices (Admin) - Requires JWT
REM ======================================================================
call :test_header "11. List All Devices (Admin)"
if defined JWT_TOKEN (
    curl -X GET "%BASE_URL%/api/v1/meters?page=1&limit=10&status=ACTIVE" ^
      -H "Authorization: Bearer %JWT_TOKEN%" ^
      -o test_results\all_devices.json ^
      -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
      -s
    call :check_result
) else (
    echo Skipping - JWT token not available
)
echo.

REM ======================================================================
REM NEGATIVE TESTS
REM ======================================================================
call :color_echo 0E "Starting Negative Tests..."
echo.

REM ======================================================================
REM TEST 12: Invalid API Key
REM ======================================================================
call :test_header "12. Invalid API Key Test"
curl -X GET %BASE_URL%/api/v1/meter/%METER_ID% ^
  -H "X-API-Key: INVALID_KEY" ^
  -o test_results\invalid_api_key.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 13: Missing Authentication
REM ======================================================================
call :test_header "13. Missing Authentication Test"
curl -X GET %BASE_URL%/api/v1/meter/%METER_ID% ^
  -o test_results\missing_auth.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST 14: Invalid Reading Data
REM ======================================================================
call :test_header "14. Invalid Reading Data Test"
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/reading ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"r_phase_current\":1500,\"reading_datetime\":\"2025-09-08T10:35:00Z\"}" ^
  -o test_results\invalid_reading.json ^
  -w "HTTP Status: %%{http_code}, Time: %%{time_total}s\n" ^
  -s
call :check_result
echo.

REM ======================================================================
REM TEST SUMMARY
REM ======================================================================
call :color_echo 0A "Test Suite Completed!"
echo.
echo ======================================================================
echo Test Results Summary
echo ======================================================================
echo All test results saved in 'test_results' directory
echo.
echo Files created:
dir test_results\*.json /b
echo.
echo ======================================================================

pause
goto :eof

REM ======================================================================
REM FUNCTIONS
REM ======================================================================

:test_header
echo ----------------------------------------------------------------------
echo %~1
echo ----------------------------------------------------------------------
goto :eof

:check_result
if %errorlevel% == 0 (
    call :color_echo 0A "✓ Test completed"
) else (
    call :color_echo 0C "✗ Test failed"
)
goto :eof

:color_echo
<nul set /p ".=%BS%" > "%2"
findstr /v /a:%1 /R "^$" "%2" nul
del "%2" > nul 2>&1
goto :eof

endlocal
