@echo off
rem Builds SentinelTwo.exe with the .NET Framework 4.8 csc compiler, restricted to C# 5.
rem Version comes from version.txt. The build copies the result to releases\<version>\.
rem An existing release file that differs from the new build is never overwritten.
setlocal
set "FX=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319"
if not exist "%FX%\csc.exe" (
  echo csc.exe not found in %FX%
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\write-version.ps1" -Root "%~dp0."
if errorlevel 1 exit /b 1
set /p VER=<"%~dp0version.txt"
set "VER=%VER: =%"

if not exist "%~dp0bin" mkdir "%~dp0bin"
pushd "%~dp0"
"%FX%\csc.exe" /nologo /target:exe /platform:x64 /langversion:5 /optimize+ ^
  /win32manifest:app.manifest /out:bin\SentinelTwo.exe ^
  /r:"%FX%\System.dll" /r:"%FX%\System.Core.dll" /r:"%FX%\System.Xml.dll" ^
  /r:"%FX%\System.Management.dll" /r:"%FX%\System.Web.Extensions.dll" ^
  /r:"%FX%\Microsoft.CSharp.dll" ^
  src\*.cs
set "RC=%ERRORLEVEL%"
popd
if not "%RC%"=="0" (
  echo Build failed with exit code %RC%
  exit /b %RC%
)
echo Build succeeded: %~dp0bin\SentinelTwo.exe (version %VER%)

set "REL=%~dp0releases\%VER%"
if exist "%REL%\SentinelTwo.exe" (
  fc /b "%REL%\SentinelTwo.exe" "%~dp0bin\SentinelTwo.exe" >nul
  if errorlevel 1 (
    echo Release %VER% already exists with different content. Not overwritten:
    echo   %REL%\SentinelTwo.exe
    echo Bump version.txt to the next PATCH version, or remove the old file deliberately.
    exit /b 3
  )
  echo Release %VER% already matches this build.
) else (
  if not exist "%REL%" mkdir "%REL%"
  copy /y "%~dp0bin\SentinelTwo.exe" "%REL%\SentinelTwo.exe" >nul
  if errorlevel 1 (
    echo Could not copy the build to %REL%
    exit /b 1
  )
  echo Copied to %REL%\SentinelTwo.exe
)
endlocal
