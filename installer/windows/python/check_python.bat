@echo off
REM Check if Python is installed and meets version requirements

SETLOCAL ENABLEDELAYEDEXPANSION

SET MIN_VERSION=3.8.0
SET PYTHON_PATH=

REM Check if Python is in PATH
python --version >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    FOR /F "tokens=2" %%I IN ('python --version 2^>^&1') DO SET CURRENT_VERSION=%%I
    ECHO Python !CURRENT_VERSION! found.
    
    REM Compare versions
    CALL :COMPARE_VERSIONS !CURRENT_VERSION! %MIN_VERSION%
    IF !ERRORLEVEL! EQU 1 (
        ECHO Python version !CURRENT_VERSION! meets minimum requirements.
        EXIT /B 0
    ) ELSE (
        ECHO Python version !CURRENT_VERSION! is too old. Minimum required: %MIN_VERSION%
        EXIT /B 1
    )
) ELSE (
    ECHO Python not found in PATH.
    
    REM Check common installation locations
    IF EXIST "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" (
        SET PYTHON_PATH=%LOCALAPPDATA%\Programs\Python\Python39\python.exe
    ) ELSE IF EXIST "%LOCALAPPDATA%\Programs\Python\Python38\python.exe" (
        SET PYTHON_PATH=%LOCALAPPDATA%\Programs\Python\Python38\python.exe
    ) ELSE IF EXIST "%PROGRAMFILES%\Python39\python.exe" (
        SET PYTHON_PATH=%PROGRAMFILES%\Python39\python.exe
    ) ELSE IF EXIST "%PROGRAMFILES%\Python38\python.exe" (
        SET PYTHON_PATH=%PROGRAMFILES%\Python38\python.exe
    ) ELSE IF EXIST "%PROGRAMFILES(X86)%\Python39\python.exe" (
        SET PYTHON_PATH=%PROGRAMFILES(X86)%\Python39\python.exe
    ) ELSE IF EXIST "%PROGRAMFILES(X86)%\Python38\python.exe" (
        SET PYTHON_PATH=%PROGRAMFILES(X86)%\Python38\python.exe
    )
    
    IF NOT "!PYTHON_PATH!" == "" (
        FOR /F "tokens=2" %%I IN ('"!PYTHON_PATH!" --version 2^>^&1') DO SET CURRENT_VERSION=%%I
        ECHO Python !CURRENT_VERSION! found at !PYTHON_PATH!.
        
        REM Compare versions
        CALL :COMPARE_VERSIONS !CURRENT_VERSION! %MIN_VERSION%
        IF !ERRORLEVEL! EQU 1 (
            ECHO Python version !CURRENT_VERSION! meets minimum requirements, but is not in PATH.
            ECHO Adding !PYTHON_PATH! to PATH...
            SETX PATH "%PATH%;%~dp0!PYTHON_PATH!"
            EXIT /B 0
        ) ELSE (
            ECHO Python version !CURRENT_VERSION! is too old. Minimum required: %MIN_VERSION%
            EXIT /B 1
        )
    ) ELSE (
        ECHO Python not found.
        EXIT /B 1
    )
)

GOTO :EOF

:COMPARE_VERSIONS
SETLOCAL
SET VERSION1=%~1
SET VERSION2=%~2

FOR /F "tokens=1,2,3 delims=." %%A IN ("%VERSION1%") DO (
    SET MAJOR1=%%A
    SET MINOR1=%%B
    SET PATCH1=%%C
)

FOR /F "tokens=1,2,3 delims=." %%A IN ("%VERSION2%") DO (
    SET MAJOR2=%%A
    SET MINOR2=%%B
    SET PATCH2=%%C
)

IF %MAJOR1% GTR %MAJOR2% EXIT /B 1
IF %MAJOR1% LSS %MAJOR2% EXIT /B 0
IF %MINOR1% GTR %MINOR2% EXIT /B 1
IF %MINOR1% LSS %MINOR2% EXIT /B 0
IF %PATCH1% GEQ %PATCH2% EXIT /B 1
EXIT /B 0 