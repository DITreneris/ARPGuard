@echo off
REM Install Python automatically

SETLOCAL ENABLEDELAYEDEXPANSION

SET PYTHON_VERSION=3.9.13
SET PYTHON_INSTALLER=python-%PYTHON_VERSION%-amd64.exe
SET DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/%PYTHON_INSTALLER%
SET TEMP_DIR=%TEMP%\arpguard_python_install

ECHO.
ECHO === Installing Python %PYTHON_VERSION% ===
ECHO.

REM Create temp directory if it doesn't exist
IF NOT EXIST "%TEMP_DIR%" mkdir "%TEMP_DIR%"

ECHO Downloading Python installer...
PowerShell -Command "& {Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%TEMP_DIR%\%PYTHON_INSTALLER%'}"
IF %ERRORLEVEL% NEQ 0 (
    ECHO Failed to download Python installer.
    EXIT /B 1
)

ECHO Download complete.
ECHO.
ECHO Installing Python...
ECHO This may take a few minutes. Please wait.
ECHO.

REM Install Python silently with key options
"%TEMP_DIR%\%PYTHON_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_doc=0 Include_launcher=1 Include_tcltk=0

IF %ERRORLEVEL% NEQ 0 (
    ECHO Failed to install Python.
    EXIT /B 1
)

ECHO.
ECHO Python installation complete.
ECHO.

REM Clean up
ECHO Cleaning up temporary files...
IF EXIST "%TEMP_DIR%\%PYTHON_INSTALLER%" del "%TEMP_DIR%\%PYTHON_INSTALLER%"
IF EXIST "%TEMP_DIR%" rmdir "%TEMP_DIR%"

ECHO.
ECHO === Python Installation Complete ===
ECHO.

REM Refresh PATH environment variable
SET PATH=%PATH%
ECHO Refreshing PATH...

EXIT /B 0 