@echo off
setlocal
cd /d "%~dp0"
set "PRESET=mingw-release"
if not "%~1"=="" set "PRESET=%~1"
if /I not "%PRESET%"=="mingw-release" if /I not "%PRESET%"=="msvc-release" (
    echo Usage: build.bat [mingw-release^|msvc-release]
    exit /b 2
)
cmake --preset "%PRESET%"
if errorlevel 1 exit /b 1
cmake --build --preset "%PRESET%"
if errorlevel 1 exit /b 1
ctest --preset "%PRESET%"
exit /b %ERRORLEVEL%
