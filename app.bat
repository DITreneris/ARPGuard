@echo off
REM Check for admin rights
NET SESSION >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    echo Running with administrator privileges...
) ELSE (
    echo ARPGuard requires administrator privileges.
    echo Right-click on this batch file and select "Run as administrator".
    pause
    exit
)

REM Run the application
python run.py
pause 