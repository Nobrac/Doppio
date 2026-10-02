@echo off
REM =====================================================================
REM  Build ONLY the two LSA pieces from Part 2, for quick iteration.
REM  The full build (credential provider + enroll.exe + LSA) is build.bat.
REM
REM  Run this from the "x64 Native Tools Command Prompt" of your Visual
REM  Studio / Build Tools version. That shell puts cl.exe and the Windows
REM  SDK on your PATH automatically.
REM
REM  WARNING: both DLLs get loaded INTO lsass.exe. A bug does not fail one
REM  tile - it can crash LSA and leave the machine unbootable, past Safe
REM  Mode. Throwaway VM with a snapshot only.
REM =====================================================================

setlocal
cd /d "%~dp0"

echo.
echo === Building TacAuthPackage.dll (LSA authentication package, SKELETON) ===
cl /nologo /LD /MT /O2 /guard:cf /EHsc /std:c++17 /W3 /DUNICODE /D_UNICODE ^
   ap.cpp store.cpp totp.cpp ^
   /Fe:TacAuthPackage.dll ^
   /link /guard:cf /DEF:TacAuthPackage.def ^
   advapi32.lib crypt32.lib bcrypt.lib
if errorlevel 1 goto :fail

echo.
echo === Building TacSubAuth.dll (MSV1_0 sub-authentication package, SKELETON) ===
cl /nologo /LD /MT /O2 /guard:cf /EHsc /std:c++17 /W3 /DUNICODE /D_UNICODE ^
   subauth.cpp store.cpp totp.cpp ^
   /Fe:TacSubAuth.dll ^
   /link /guard:cf /DEF:TacSubAuth.def ^
   advapi32.lib crypt32.lib bcrypt.lib
if errorlevel 1 goto :fail

echo.
echo === Done. Cleaning up intermediate files ===
del /q *.obj *.exp 2>nul

echo.
echo Built: TacAuthPackage.dll, TacSubAuth.dll
echo Both run INSIDE lsass.exe. Snapshot the VM before you reboot.
goto :eof

:fail
echo.
echo BUILD FAILED - see the compiler errors above.
exit /b 1
