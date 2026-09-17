@echo off
rem A marker helper for the restricted-profile fixture, for Windows hosts.
rem
rem See marker.sh: @SENTINELS@ is replaced with an absolute directory when the fixture is planted,
rem and a run writes a file named after the entry that invoked it.
setlocal
set "sentinels=@SENTINELS@"
set "name=%~1"
if "%name%"=="" set "name=unknown"
if not exist "%sentinels%" mkdir "%sentinels%" >nul 2>&1
echo %name%>>"%sentinels%\%name%"
exit /b 0
