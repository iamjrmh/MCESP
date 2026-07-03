@echo off
SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
SET "SCRIPT_DIR=%~dp0"
SET "MCESP_PATH=%SCRIPT_DIR%MCESP.py"
SET "RELEASE_PATH=%SCRIPT_DIR%release.md"
SET "HELPER_PATH=%SCRIPT_DIR%bump_helper.ps1"

CALL :main
GOTO :end

:main
    IF NOT EXIST "%MCESP_PATH%" (
        ECHO ERROR: MCESP.py not found next to bump.bat
        EXIT /B 1
    )
    IF NOT EXIST "%HELPER_PATH%" (
        ECHO ERROR: bump_helper.ps1 not found next to bump.bat
        EXIT /B 1
    )

    FOR /F "usebackq delims=" %%V IN (`powershell -NoProfile -ExecutionPolicy Bypass -File "%HELPER_PATH%" -Mode Get -Path "%MCESP_PATH%"`) DO SET "CURRENT_VERSION=%%V"

    IF NOT DEFINED CURRENT_VERSION (
        ECHO ERROR: could not find a VERSION = "X.X.X" line in MCESP.py
        EXIT /B 1
    )

    ECHO MCESP Version Bumper
    ECHO =====================
    ECHO Current version: %CURRENT_VERSION%
    ECHO.
    SET "NEW_VERSION="
    SET /P NEW_VERSION=Enter new version (X.X.X):

    IF NOT DEFINED NEW_VERSION (
        ECHO No version entered, exiting.
        EXIT /B 0
    )

    ECHO %NEW_VERSION%| findstr /R "^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" >nul
    IF ERRORLEVEL 1 (
        ECHO ERROR: version must look like X.X.X ^(e.g. 2.1.0^)
        EXIT /B 1
    )

    powershell -NoProfile -ExecutionPolicy Bypass -File "%HELPER_PATH%" -Mode Set -Path "%MCESP_PATH%" -ReleasePath "%RELEASE_PATH%" -NewVersion "%NEW_VERSION%" > "%TEMP%\mcesp_bump_out.txt"
    IF ERRORLEVEL 1 (
        ECHO ERROR: failed to update MCESP.py
        EXIT /B 1
    )

    FINDSTR /C:"release_updated" "%TEMP%\mcesp_bump_out.txt" >nul
    IF ERRORLEVEL 1 (
        ECHO Updated MCESP.py ^(release.md not found, skipped^)
    ) ELSE (
        ECHO Updated MCESP.py and release.md
    )
    DEL /Q "%TEMP%\mcesp_bump_out.txt" >nul 2>&1

    ECHO.
    ECHO Version bumped: %CURRENT_VERSION% -^> %NEW_VERSION%
    ECHO.
    ECHO Next steps:
    ECHO   1. Commit and push MCESP.py (and release.md if changed)
    ECHO   2. Create a GitHub Release tagged v%NEW_VERSION% with MCESP.exe attached
    ECHO      -- that's what buddies' Check for Updates button reads
    EXIT /B 0

:error
    ECHO [ERROR] bump.bat failed with code %ERRORLEVEL% 1>&2
    EXIT /B %ERRORLEVEL%

:end
ECHO.
PAUSE
ENDLOCAL
