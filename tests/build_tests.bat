@echo off
rem Builds the SentinelTwo test runner with the .NET Framework 4.8 csc compiler, C# 5 only.
rem The test build has no administrator manifest, so unit tests run unelevated.
rem Run:  bin\SentinelTwo.Tests.exe               (unit tests)
rem       bin\SentinelTwo.Tests.exe --integration (also touches the live machine; see IntegrationTests.cs)
setlocal
set "FX=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319"
if not exist "%FX%\csc.exe" (
  echo csc.exe not found in %FX%
  exit /b 1
)
set "ROOT=%~dp0.."
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\tools\write-version.ps1" -Root "%ROOT%"
if errorlevel 1 exit /b 1
if not exist "%~dp0bin" mkdir "%~dp0bin"
pushd "%ROOT%"
"%FX%\csc.exe" /nologo /target:exe /platform:x64 /langversion:5 /debug- /optimize+ ^
  /main:SentinelTwo.Tests.Runner /out:tests\bin\SentinelTwo.Tests.exe ^
  /r:"%FX%\System.dll" /r:"%FX%\System.Core.dll" /r:"%FX%\System.Xml.dll" ^
  /r:"%FX%\System.Management.dll" /r:"%FX%\System.Web.Extensions.dll" ^
  /r:"%FX%\Microsoft.CSharp.dll" ^
  src\*.cs tests\*.cs
set "RC=%ERRORLEVEL%"
popd
if not "%RC%"=="0" (
  echo Test build failed with exit code %RC%
  exit /b %RC%
)
echo Test build succeeded: %~dp0bin\SentinelTwo.Tests.exe
endlocal
