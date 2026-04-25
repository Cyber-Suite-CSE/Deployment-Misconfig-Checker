@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Minimal vulnerable WP lab - dynamically installs plugins from vulnerable_plugins.txt
rem Usage:
rem   setup.bat          normal run
rem   setup.bat --reset  stop and delete volumes (fresh DB/files)

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul

if defined PORT (
    set "PORT_VALUE=%PORT%"
) else (
    set "PORT_VALUE=31337"
)

set "IMG_NAME=vuln-wordpress"
set "COMPOSE_FILE=docker-compose.yaml"
if not exist "%COMPOSE_FILE%" if exist "docker-compose.yml" set "COMPOSE_FILE=docker-compose.yml"
set "PLUGINS_DIR=wp-content\plugins"
set "PLUGINS_LIST=vulnerable_plugins.txt"

if /I "%~1"=="--reset" (
    echo Reset requested: stopping and deleting volumes...
    docker compose -f "%COMPOSE_FILE%" down -v
)

echo Installing vulnerable plugins from %PLUGINS_LIST%...
if not exist "%PLUGINS_DIR%" mkdir "%PLUGINS_DIR%"

if not exist "%PLUGINS_LIST%" (
    echo Error: %PLUGINS_LIST% not found
    popd >nul
    exit /b 1
)

for /f "usebackq tokens=1-4 delims=|" %%A in ("%PLUGINS_LIST%") do (
    set "plugin_name=%%~A"
    set "version=%%~B"
    set "download_url=%%~C"
    set "cve_id=%%~D"

    if defined plugin_name (
        if not "!plugin_name:~0,1!"=="#" (
            set "zip_name=!plugin_name!-!version!.zip"

            echo Fetching !plugin_name! ^(v!version!^) - !cve_id!...
            powershell -NoProfile -ExecutionPolicy Bypass -Command ^
                "Invoke-WebRequest -Uri '!download_url!' -OutFile '%PLUGINS_DIR%\!zip_name!'" || (
                    echo PowerShell download failed, trying curl.exe...
                    curl.exe -fL "!download_url!" -o "%PLUGINS_DIR%\!zip_name!" || (
                        echo Error: failed to download !plugin_name!
                        popd >nul
                        exit /b 1
                    )
                )

            echo Extracting !zip_name!...
            powershell -NoProfile -ExecutionPolicy Bypass -Command ^
                "Expand-Archive -LiteralPath '%PLUGINS_DIR%\!zip_name!' -DestinationPath '%PLUGINS_DIR%' -Force" || (
                    echo Error: failed to extract !zip_name!
                    popd >nul
                    exit /b 1
                )

            del /f /q "%PLUGINS_DIR%\!zip_name!" >nul 2>&1
            echo [OK] !plugin_name! v!version! installed ^(!cve_id!^)
        )
    )
)

echo Building WordPress image...
docker build -t "%IMG_NAME%:latest" . || (
    echo Error: docker build failed
    popd >nul
    exit /b 1
)

echo Starting containers...
docker compose -f "%COMPOSE_FILE%" up -d || (
    echo Error: docker compose up failed
    popd >nul
    exit /b 1
)

echo.
echo Up and running!
echo.
echo Open WordPress installer:
echo   http://localhost:%PORT_VALUE%
echo.
echo Database ^(auto-configured^):
echo   host: db
echo   name: wordpress
echo   user: wordpress
echo   pass: wordpress
echo.
echo Then in WP Admin:
echo   Go to Plugins and activate the vulnerable plugins.
echo.
echo Common ops:
echo   Stop stack:      docker compose -f "%COMPOSE_FILE%" down
echo   Reset ^(wipe DB^): setup.bat --reset
echo.
echo WARNING: This lab is intentionally vulnerable. Do NOT expose it to the internet.

popd >nul
exit /b 0
