@echo off
REM ======================================================================
REM Smart Meter API Master Test Runner - DOS Batch File
REM ======================================================================

setlocal enabledelayedexpansion

REM Configuration
set BASE_URL=http://localhost:3000
set API_KEY=ESP32_18_1757319009493_1b2aad987f9460d3
set METER_ID=18

echo ======================================================================
echo Smart Meter API Master Test Runner
echo ======================================================================
echo.
echo This script will run comprehensive tests on the Smart Meter API
echo.
echo Available Test Suites:
echo 1. Full API Test Suite (All endpoints)
echo 2. Rate Limit Testing
echo 3. Load Testing
echo 4. Continuous Monitoring
echo 5. Quick Health Check
echo 6. Run All Tests (1-3)
echo 7. Exit
echo.

:menu
set /p choice="Please select a test suite (1-7): "

if "%choice%"=="1" goto full_test
if "%choice%"=="2" goto rate_limit_test
if "%choice%"=="3" goto load_test
if "%choice%"=="4" goto monitoring_test
if "%choice%"=="5" goto health_check
if "%choice%"=="6" goto run_all
if "%choice%"=="7" goto exit
echo Invalid choice. Please try again.
goto menu

:full_test
echo.
echo ======================================================================
echo Running Full API Test Suite...
echo ======================================================================
call :run_full_api_tests
goto show_menu

:rate_limit_test
echo.
echo ======================================================================
echo Running Rate Limit Tests...
echo ======================================================================
call :run_rate_limit_tests
goto show_menu

:load_test
echo.
echo ======================================================================
echo Running Load Tests...
echo ======================================================================
call :run_load_tests
goto show_menu

:monitoring_test
echo.
echo ======================================================================
echo Starting Continuous Monitoring...
echo ======================================================================
echo Press Ctrl+C to stop monitoring and return to menu
call :run_monitoring_tests
goto show_menu

:health_check
echo.
echo ======================================================================
echo Running Quick Health Check...
echo ======================================================================
call :run_health_check
goto show_menu

:run_all
echo.
echo ======================================================================
echo Running All Automated Tests (excluding monitoring)...
echo ======================================================================
call :run_full_api_tests
echo.
call :run_rate_limit_tests
echo.
call :run_load_tests
goto show_menu

:show_menu
echo.
echo ======================================================================
echo Tests completed. Returning to main menu...
echo ======================================================================
echo.
goto menu

:exit
echo.
echo Exiting Smart Meter API Test Runner...
exit /b

REM ======================================================================
REM TEST FUNCTIONS
REM ======================================================================

:run_health_check
echo Checking API health...
curl -X GET %BASE_URL%/health ^
  -w "Health Check - HTTP Status: %%{http_code}, Response Time: %%{time_total}s\n" ^
  -s -o health_quick.json

if %errorlevel% == 0 (
    echo ✓ API is responding
    type health_quick.json | findstr "status"
) else (
    echo ✗ API is not responding
)
del health_quick.json >nul 2>&1
goto :eof

:run_full_api_tests
REM Create results directory
if not exist "api_test_results" mkdir api_test_results

echo Running comprehensive API tests...

REM Test 1: Health Check
echo 1/11: Health Check
curl -X GET %BASE_URL%/health -o api_test_results\01_health.json -s -w "%%{http_code}" > api_test_results\01_status.txt
call :check_status api_test_results\01_status.txt "Health Check"

REM Test 2: Device Info
echo 2/11: Device Information
curl -X GET %BASE_URL%/api/v1/meter/%METER_ID% ^
  -H "X-API-Key: %API_KEY%" ^
  -o api_test_results\02_device_info.json -s -w "%%{http_code}" > api_test_results\02_status.txt
call :check_status api_test_results\02_status.txt "Device Info"

REM Test 3: Device Config
echo 3/11: Device Configuration
curl -X GET %BASE_URL%/api/v1/meter/%METER_ID%/config ^
  -H "X-API-Key: %API_KEY%" ^
  -o api_test_results\03_device_config.json -s -w "%%{http_code}" > api_test_results\03_status.txt
call :check_status api_test_results\03_status.txt "Device Config"

REM Test 4: Submit Reading
echo 4/11: Submit Single Reading
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/reading ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"reading_datetime\":\"2025-09-08T10:35:00Z\",\"r_phase_current\":12.5,\"y_phase_current\":11.8,\"b_phase_current\":13.2,\"r_phase_voltage\":230.5,\"y_phase_voltage\":229.8,\"b_phase_voltage\":231.2,\"kw_import\":8.5,\"kw_export\":0.0,\"kva_import\":9.2,\"kva_export\":0.0,\"kwh_import\":12450.5,\"kwh_export\":125.2,\"kvah_import\":13200.8,\"kvah_export\":145.5}" ^
  -o api_test_results\04_single_reading.json -s -w "%%{http_code}" > api_test_results\04_status.txt
call :check_status api_test_results\04_status.txt "Single Reading"

REM Test 5: Batch Readings
echo 5/11: Submit Batch Readings
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/readings/batch ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"readings\":[{\"reading_datetime\":\"2025-09-08T10:30:00Z\",\"r_phase_current\":12.1,\"y_phase_current\":11.5,\"b_phase_current\":12.8,\"r_phase_voltage\":230.2,\"y_phase_voltage\":229.5,\"b_phase_voltage\":230.8,\"kw_import\":8.2,\"kwh_import\":12448.3},{\"reading_datetime\":\"2025-09-08T10:35:00Z\",\"r_phase_current\":12.5,\"y_phase_current\":11.8,\"b_phase_current\":13.2,\"r_phase_voltage\":230.5,\"y_phase_voltage\":229.8,\"b_phase_voltage\":231.2,\"kw_import\":8.5,\"kwh_import\":12450.5}]}" ^
  -o api_test_results\05_batch_readings.json -s -w "%%{http_code}" > api_test_results\05_status.txt
call :check_status api_test_results\05_status.txt "Batch Readings"

REM Test 6: TOD Readings
echo 6/11: Submit TOD Readings
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/tod-readings ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"tod_readings\":[{\"tod_period\":1,\"reading_datetime\":\"2025-09-08T10:30:00Z\",\"kwh_import\":1250.5,\"kwh_export\":15.2,\"kvah_import\":1320.8,\"kvah_export\":18.5},{\"tod_period\":2,\"reading_datetime\":\"2025-09-08T10:30:00Z\",\"kwh_import\":2100.3,\"kwh_export\":25.8,\"kvah_import\":2250.4,\"kvah_export\":28.2}]}" ^
  -o api_test_results\06_tod_readings.json -s -w "%%{http_code}" > api_test_results\06_status.txt
call :check_status api_test_results\06_status.txt "TOD Readings"

REM Test 7: Heartbeat
echo 7/11: Device Heartbeat
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/heartbeat ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"firmware_version\":\"1.2.3\",\"battery_level\":85,\"signal_strength\":-45,\"uptime\":3600,\"free_heap\":45000,\"wifi_rssi\":-55,\"temperature\":35.5,\"error_count\":0,\"last_restart_reason\":\"POWER_ON\"}" ^
  -o api_test_results\07_heartbeat.json -s -w "%%{http_code}" > api_test_results\07_status.txt
call :check_status api_test_results\07_status.txt "Heartbeat"

REM Test 8: Latest Readings
echo 8/11: Get Latest Readings
curl -X GET "%BASE_URL%/api/v1/meter/%METER_ID%/readings/latest?limit=5" ^
  -H "X-API-Key: %API_KEY%" ^
  -o api_test_results\08_latest_readings.json -s -w "%%{http_code}" > api_test_results\08_status.txt
call :check_status api_test_results\08_status.txt "Latest Readings"

REM Test 9: Invalid API Key
echo 9/11: Invalid API Key Test
curl -X GET %BASE_URL%/api/v1/meter/%METER_ID% ^
  -H "X-API-Key: INVALID_KEY" ^
  -o api_test_results\09_invalid_key.json -s -w "%%{http_code}" > api_test_results\09_status.txt
set /p status=<api_test_results\09_status.txt
if "%status%"=="401" (
    echo ✓ Invalid API Key ^(Expected 401^)
) else (
    echo ✗ Invalid API Key ^(Got %status%, Expected 401^)
)

REM Test 10: Missing Auth
echo 10/11: Missing Authentication Test
curl -X GET %BASE_URL%/api/v1/meter/%METER_ID% ^
  -o api_test_results\10_missing_auth.json -s -w "%%{http_code}" > api_test_results\10_status.txt
set /p status=<api_test_results\10_status.txt
if "%status%"=="401" (
    echo ✓ Missing Auth ^(Expected 401^)
) else (
    echo ✗ Missing Auth ^(Got %status%, Expected 401^)
)

REM Test 11: Invalid Data
echo 11/11: Invalid Reading Data Test
curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/reading ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"r_phase_current\":1500,\"reading_datetime\":\"2025-09-08T10:35:00Z\"}" ^
  -o api_test_results\11_invalid_data.json -s -w "%%{http_code}" > api_test_results\11_status.txt
set /p status=<api_test_results\11_status.txt
if "%status%"=="400" (
    echo ✓ Invalid Data ^(Expected 400^)
) else (
    echo ✗ Invalid Data ^(Got %status%, Expected 400^)
)

echo.
echo Full API test completed. Results saved in 'api_test_results' directory.
goto :eof

:run_rate_limit_tests
if not exist "rate_limit_results" mkdir rate_limit_results

echo Testing rate limits ^(sending 15 requests, limit is 10/minute^)...
set success_count=0
set rate_limited_count=0

for /l %%i in (1,1,15) do (
    curl -X GET %BASE_URL%/api/v1/meter/%METER_ID%/config ^
      -H "X-API-Key: %API_KEY%" ^
      -o rate_limit_results\req_%%i.json -s -w "%%{http_code}" > rate_limit_results\status_%%i.txt
    
    set /p status=<rate_limit_results\status_%%i.txt
    if "!status!"=="200" (
        set /a success_count+=1
        echo Request %%i: ✓ Success
    ) else if "!status!"=="429" (
        set /a rate_limited_count+=1
        echo Request %%i: ⚠ Rate Limited
    ) else (
        echo Request %%i: ✗ Error ^(!status!^)
    )
    
    timeout /t 2 /nobreak >nul
)

echo.
echo Rate Limit Test Results:
echo Successful requests: !success_count!
echo Rate limited requests: !rate_limited_count!
echo Expected: 10 successful, 5 rate limited
goto :eof

:run_load_tests
if not exist "load_test_results" mkdir load_test_results

echo Running load test ^(50 requests^)...
set success=0
set errors=0

for /l %%i in (1,1,50) do (
    curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/reading ^
      -H "Content-Type: application/json" ^
      -H "X-API-Key: %API_KEY%" ^
      -d "{\"reading_datetime\":\"2025-09-08T10:35:00Z\",\"r_phase_current\":12.5,\"y_phase_current\":11.8,\"b_phase_current\":13.2,\"r_phase_voltage\":230.5,\"y_phase_voltage\":229.8,\"b_phase_voltage\":231.2,\"kw_import\":8.5,\"kwh_import\":12450.5}" ^
      -o load_test_results\load_%%i.json -s -w "%%{http_code}" > load_test_results\load_status_%%i.txt
    
    set /p status=<load_test_results\load_status_%%i.txt
    if "!status!"=="200" (
        set /a success+=1
    ) else (
        set /a errors+=1
    )
    
    if %%i LEQ 10 echo Request %%i: !status!
    if %%i GTR 10 if %%i LEQ 20 if %%i==11 echo ... ^(showing every 10th request^) ...
    if %%i GTR 10 (
        set /a mod=%%i%%10
        if !mod!==0 echo Request %%i: !status!
    )
    
    timeout /t 1 /nobreak >nul
)

echo.
echo Load Test Results:
echo Successful requests: !success!/50
echo Failed requests: !errors!/50
echo Success rate: !success!%%
goto :eof

:run_monitoring_tests
echo Starting continuous monitoring...
echo Sending heartbeat and readings every 30 seconds
echo Press Ctrl+C to stop

if not exist "monitoring_results" mkdir monitoring_results
set counter=1

:monitor_loop
echo [%date% %time%] Monitoring cycle !counter!

curl -X POST %BASE_URL%/api/v1/meter/%METER_ID%/heartbeat ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %API_KEY%" ^
  -d "{\"firmware_version\":\"1.2.3\",\"battery_level\":85,\"signal_strength\":-45,\"uptime\":3600,\"free_heap\":45000,\"wifi_rssi\":-55,\"temperature\":35.5,\"error_count\":0,\"last_restart_reason\":\"POWER_ON\"}" ^
  -o monitoring_results\monitor_!counter!.json -s -w "Monitoring !counter! - HTTP: %%{http_code}, Time: %%{time_total}s\n"

set /a counter+=1
timeout /t 30 /nobreak >nul
goto monitor_loop

:check_status
set /p status=<%1
if "%status%"=="200" (
    echo ✓ %2
) else (
    echo ✗ %2 ^(HTTP %status%^)
)
goto :eof

endlocal