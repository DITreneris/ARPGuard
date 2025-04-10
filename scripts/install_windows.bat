@echo off
:: ARP Guard Windows Installation Script
:: This batch file helps install ARP Guard on Windows systems

echo.
echo ===== ARP Guard Windows Installer =====
echo.

:: Check for administrative privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: This script requires administrative privileges.
    echo Please right-click Command Prompt and select "Run as administrator"
    pause
    exit /b 1
)

echo Checking for administrative privileges... OK

:: Set configuration variables
set INSTALL_DIR=%ProgramFiles%\ARP Guard
set PYTHON_URL=https://www.python.org/ftp/python/3.10.5/python-3.10.5-amd64.exe
set NPCAP_URL=https://nmap.org/npcap/dist/npcap-1.50.exe
set DOWNLOAD_DIR=%TEMP%\arp-guard-install
set GITHUB_URL=https://github.com/yourorg/arp-guard/archive/refs/heads/main.zip
set GITHUB_ZIP=%DOWNLOAD_DIR%\arp-guard.zip
set EXTRACTED_DIR=%DOWNLOAD_DIR%\arp-guard-main

:: Create download directory
if not exist %DOWNLOAD_DIR% mkdir %DOWNLOAD_DIR%

:: Step 1: Check for Python
echo.
echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python not found. Would you like to download and install Python?
    choice /c YN /m "Download Python now"
    if errorlevel 2 (
        echo Python is required for ARP Guard. Installation aborted.
        goto :cleanup
    )
    
    echo Downloading Python installer...
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%DOWNLOAD_DIR%\python-installer.exe'}"
    if %errorlevel% neq 0 (
        echo Failed to download Python installer.
        goto :cleanup
    )
    
    echo Installing Python...
    %DOWNLOAD_DIR%\python-installer.exe /quiet InstallAllUsers=1 PrependPath=1
    if %errorlevel% neq 0 (
        echo Python installation failed.
        goto :cleanup
    )
    
    :: Update PATH to include Python without requiring restart
    for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path') do set CURRENT_PATH=%%b
    setx PATH "%CURRENT_PATH%;%ProgramFiles%\Python310;%ProgramFiles%\Python310\Scripts" /M
    set PATH=%PATH%;%ProgramFiles%\Python310;%ProgramFiles%\Python310\Scripts

    echo Python installed successfully.
) else (
    echo Python is already installed.
)

:: Step 2: Check for pip
echo.
echo Checking pip installation...
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo pip not found. Installing pip...
    python -m ensurepip --upgrade
    if %errorlevel% neq 0 (
        echo Failed to install pip.
        goto :cleanup
    )
)
echo pip is ready.

:: Step 3: Check for Npcap/WinPcap
echo.
echo Checking Npcap/WinPcap installation...
if not exist %SystemRoot%\System32\wpcap.dll (
    if not exist "%ProgramFiles%\Npcap\wpcap.dll" (
        echo Npcap/WinPcap not found. Would you like to download and install Npcap?
        choice /c YN /m "Download Npcap now"
        if errorlevel 2 (
            echo Warning: Npcap is required for packet capture. ARP Guard may not function correctly.
        ) else (
            echo Downloading Npcap installer...
            powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%NPCAP_URL%' -OutFile '%DOWNLOAD_DIR%\npcap-installer.exe'}"
            if %errorlevel% neq 0 (
                echo Failed to download Npcap installer.
                goto :cleanup
            )
            
            echo Installing Npcap...
            %DOWNLOAD_DIR%\npcap-installer.exe /S
            if %errorlevel% neq 0 (
                echo Npcap installation failed.
                goto :cleanup
            )
            echo Npcap installed successfully.
        )
    ) else (
        echo Npcap is already installed.
    )
) else (
    echo WinPcap/Npcap is already installed.
)

:: Step 4: Install Python dependencies
echo.
echo Installing Python dependencies...
pip install scapy colorama pywin32 click pyyaml python-dotenv
if %errorlevel% neq 0 (
    echo Failed to install Python dependencies.
    goto :cleanup
)
echo Python dependencies installed successfully.

:: Step 5: Create installation directory
echo.
echo Creating installation directory...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if %errorlevel% neq 0 (
    echo Failed to create installation directory.
    goto :cleanup
)

:: Step 6: Download ARP Guard
echo.
echo Downloading ARP Guard from GitHub...
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%GITHUB_URL%' -OutFile '%GITHUB_ZIP%'}"
if %errorlevel% neq 0 (
    echo Failed to download ARP Guard.
    goto :cleanup
)

:: Step 7: Extract ARP Guard
echo.
echo Extracting files...
powershell -Command "& {Expand-Archive -Path '%GITHUB_ZIP%' -DestinationPath '%DOWNLOAD_DIR%' -Force}"
if %errorlevel% neq 0 (
    echo Failed to extract ARP Guard.
    goto :cleanup
)

:: Step 8: Copy files to installation directory
echo.
echo Copying files to installation directory...
xcopy /E /I /Y "%EXTRACTED_DIR%\*" "%INSTALL_DIR%"
if %errorlevel% neq 0 (
    echo Failed to copy files to installation directory.
    goto :cleanup
)

:: Step 9: Install ARP Guard
echo.
echo Installing ARP Guard package...
cd /d "%INSTALL_DIR%"
pip install -e .
if %errorlevel% neq 0 (
    echo Failed to install ARP Guard package.
    goto :cleanup
)

:: Step 10: Create batch file for easy execution
echo.
echo Creating arp-guard.bat file...
set BATCH_FILE=%INSTALL_DIR%\scripts\arp-guard.bat
(
    echo @echo off
    echo python "%INSTALL_DIR%\src\main.py" %%*
) > "%BATCH_FILE%"

:: Step 11: Add to PATH
echo.
echo Adding ARP Guard to PATH...
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path') do set CURRENT_PATH=%%b
setx PATH "%CURRENT_PATH%;%INSTALL_DIR%\scripts" /M
if %errorlevel% neq 0 (
    echo Warning: Failed to add ARP Guard to PATH.
    echo You may need to manually add %INSTALL_DIR%\scripts to your PATH.
) else (
    echo Added ARP Guard to PATH successfully.
)

:: Step 12: Verify installation
echo.
echo Verifying installation...
%INSTALL_DIR%\scripts\arp-guard.bat --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Warning: Installation verification failed.
    echo ARP Guard may not be properly installed.
) else (
    echo Installation verified successfully.
)

:: Success message
echo.
echo ===== Installation Complete =====
echo.
echo ARP Guard has been installed to %INSTALL_DIR%
echo.
echo To use ARP Guard, open a new Command Prompt and type:
echo   arp-guard --help
echo.
echo For documentation, visit:
echo   https://github.com/yourorg/arp-guard/blob/main/README.md
echo.
goto :end

:cleanup
echo.
echo Cleaning up temporary files...
if exist %DOWNLOAD_DIR% rmdir /S /Q %DOWNLOAD_DIR%
echo.
echo Installation failed. Please check the error messages above.
exit /b 1

:end
echo Cleaning up temporary files...
if exist %DOWNLOAD_DIR% rmdir /S /Q %DOWNLOAD_DIR%
echo.
pause
exit /b 0 