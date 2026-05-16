@echo off
setlocal enabledelayedexpansion

REM Anibus Windows build helper.
REM - Prefers JDK 21 (project target)
REM - Runs tests and produces shaded jar in repo root

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul

REM Resolve JAVA_HOME (prefer existing value if valid)
if defined JAVA_HOME (
  if exist "%JAVA_HOME%\\bin\\java.exe" (
    goto :java_ok
  )
)

REM Common install locations
if exist "C:\\Program Files\\Java\\jdk-21.0.10\\bin\\java.exe" (
  set "JAVA_HOME=C:\\Program Files\\Java\\jdk-21.0.10"
  goto :java_ok
)

for /f "delims=" %%D in ('dir /b /ad "C:\\Program Files\\Eclipse Adoptium\\jdk-21*" 2^>nul') do (
  if exist "C:\\Program Files\\Eclipse Adoptium\\%%D\\bin\\java.exe" (
    set "JAVA_HOME=C:\\Program Files\\Eclipse Adoptium\\%%D"
    goto :java_ok
  )
)

echo [ERROR] JAVA_HOME is not set or invalid.
echo Install JDK 21 and set JAVA_HOME to the JDK root directory.
echo Example:
echo   setx JAVA_HOME "C:\Program Files\Java\jdk-21.0.10"
exit /b 1

:java_ok
set "PATH=%JAVA_HOME%\\bin;%PATH%"

echo [INFO] Using JAVA_HOME=%JAVA_HOME%
java -version
if errorlevel 1 exit /b 1

if "%1"=="test" goto :do_test
if "%1"=="package" goto :do_package
if "%1"=="run" goto :do_run

echo.
echo Usage:
echo   build.bat test    ^(run unit tests^)
echo   build.bat package ^(build shaded jar^)
echo   build.bat run     ^(build and launch jar^)
echo.
echo Default: test + package
echo.

:do_test
call "%SCRIPT_DIR%mvnw.cmd" -q test
if errorlevel 1 exit /b 1

:do_package
call "%SCRIPT_DIR%mvnw.cmd" -q clean package
if errorlevel 1 exit /b 1

if not "%1"=="run" goto :done

:do_run
if not exist "%SCRIPT_DIR%anibus-2.2.0.jar" (
  echo [ERROR] anibus-2.2.0.jar not found in repo root.
  echo Run: build.bat package
  exit /b 1
)
echo [INFO] Launching anibus-2.2.0.jar ...
java -jar "%SCRIPT_DIR%anibus-2.2.0.jar"

:done
popd >nul
endlocal
exit /b 0

