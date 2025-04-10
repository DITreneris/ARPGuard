@echo off
REM Install Python dependencies for ARP Guard

SETLOCAL ENABLEDELAYEDEXPANSION

SET REQUIREMENTS=%~dp0requirements.txt
SET PIP_FLAGS=--no-cache-dir --use-feature=2020-resolver

ECHO.
ECHO === Installing Python Dependencies ===
ECHO.

REM Update pip
ECHO Updating pip...
python -m pip install --upgrade pip %PIP_FLAGS%
IF %ERRORLEVEL% NEQ 0 (
    ECHO Failed to update pip.
    EXIT /B 1
)

REM Install wheel for better package compatibility
ECHO Installing wheel...
python -m pip install wheel %PIP_FLAGS%

REM Check if requirements file exists
IF NOT EXIST "%REQUIREMENTS%" (
    ECHO Creating requirements file...
    (
        ECHO scapy==2.5.0
        ECHO flask==2.2.3
        ECHO flask-socketio==5.3.2
        ECHO colorama==0.4.6
        ECHO pywin32==306
        ECHO click==8.1.3
        ECHO pyyaml==6.0
        ECHO python-dotenv==1.0.0
        ECHO fastapi==0.95.0
        ECHO uvicorn==0.21.1
        ECHO websockets==11.0.1
        ECHO psutil==5.9.4
        ECHO pandas==2.0.0
        ECHO numpy==1.24.2
        ECHO sqlalchemy==2.0.9
        ECHO aiohttp==3.8.4
        ECHO pytest==7.3.1
        ECHO pytest-cov==4.1.0
    ) > "%REQUIREMENTS%"
)

ECHO Installing required packages from %REQUIREMENTS%...
python -m pip install -r "%REQUIREMENTS%" %PIP_FLAGS%
IF %ERRORLEVEL% NEQ 0 (
    ECHO Some packages failed to install. You may need to install them manually.
    EXIT /B 1
)

ECHO.
ECHO === Checking for Npcap/WinPcap ===
ECHO.

REM Check for Npcap/WinPcap
IF EXIST "%WINDIR%\System32\wpcap.dll" (
    ECHO Npcap/WinPcap found.
) ELSE IF EXIST "%WINDIR%\System32\Npcap\wpcap.dll" (
    ECHO Npcap found.
) ELSE (
    ECHO Npcap/WinPcap not found. Downloading Npcap installer...
    SET NPCAP_INSTALLER=%TEMP%\npcap-installer.exe
    SET NPCAP_URL=https://nmap.org/npcap/dist/npcap-1.60.exe
    
    PowerShell -Command "& {Invoke-WebRequest -Uri '%NPCAP_URL%' -OutFile '%NPCAP_INSTALLER%'}"
    IF %ERRORLEVEL% NEQ 0 (
        ECHO Failed to download Npcap installer.
        EXIT /B 1
    )
    
    ECHO Installing Npcap...
    %NPCAP_INSTALLER% /S /winpcap_mode=yes
    
    ECHO Cleaning up...
    IF EXIST "%NPCAP_INSTALLER%" del "%NPCAP_INSTALLER%"
)

ECHO.
ECHO === Installation Complete ===
ECHO.

EXIT /B 0 