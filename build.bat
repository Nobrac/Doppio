@echo off
REM =====================================================================
REM  Build TacProvider.dll, enroll.exe, and the LSA pieces in one shot.
REM
REM  Run this from the "x64 Native Tools Command Prompt" of your Visual
REM  Studio / Build Tools version (Start menu -> Visual Studio folder). That shell puts
REM  cl.exe and the Windows SDK on your PATH automatically.
REM
REM  Usage:   build.bat
REM  /MT links the C++ runtime statically, so the target machine needs
REM  no Visual C++ Redistributable. /O2 optimizes, /guard:cf turns on Control
REM  Flow Guard, /sdl adds extra runtime checks and turns a few dangerous
REM  warnings into errors - worth having in anything LogonUI or lsass loads.
REM =====================================================================

setlocal
cd /d "%~dp0"

echo.
echo === Building TacProvider.dll (credential provider + filter) ===
cl /nologo /LD /MT /O2 /guard:cf /EHsc /std:c++17 /W4 /sdl /DUNICODE /D_UNICODE ^
   dll.cpp CTacProvider.cpp CTacCredential.cpp CTacFilter.cpp ^
   helpers.cpp totp.cpp store.cpp verify.cpp statelock.cpp eventlog.cpp ^
   /Fe:TacProvider.dll ^
   /link /guard:cf /DEF:TacProvider.def ^
   bcrypt.lib crypt32.lib advapi32.lib secur32.lib shlwapi.lib ole32.lib uuid.lib gdi32.lib user32.lib wtsapi32.lib
if errorlevel 1 goto :fail

echo.
echo === Building enroll.exe (enrollment tool) ===
cl /nologo /MT /O2 /guard:cf /EHsc /std:c++17 /W4 /sdl /DUNICODE /D_UNICODE ^
   enroll.cpp totp.cpp store.cpp statelock.cpp ^
   /Fe:enroll.exe ^
   /link /guard:cf bcrypt.lib crypt32.lib advapi32.lib
if errorlevel 1 goto :fail

echo.
echo === Building TacAuthPackage.dll (LSA authentication package, SKELETON) ===
echo     Runs in lsass.exe. Only load it in a throwaway VM with a snapshot.
cl /nologo /LD /MT /O2 /guard:cf /EHsc /std:c++17 /W4 /sdl /DUNICODE /D_UNICODE ^
   ap.cpp store.cpp totp.cpp ^
   /Fe:TacAuthPackage.dll ^
   /link /guard:cf /DEF:TacAuthPackage.def ^
   advapi32.lib crypt32.lib bcrypt.lib
if errorlevel 1 goto :fail

echo.
echo === Building TacSubAuth.dll (MSV1_0 sub-authentication package, SKELETON) ===
echo     Runs in lsass.exe. Only load it in a throwaway VM with a snapshot.
cl /nologo /LD /MT /O2 /guard:cf /EHsc /std:c++17 /W4 /sdl /DUNICODE /D_UNICODE ^
   subauth.cpp store.cpp totp.cpp ^
   /Fe:TacSubAuth.dll ^
   /link /guard:cf /DEF:TacSubAuth.def ^
   advapi32.lib crypt32.lib bcrypt.lib
if errorlevel 1 goto :fail

echo.
echo === Done. Cleaning up intermediate files ===
del /q *.obj *.exp 2>nul

echo.
echo Built: TacProvider.dll, enroll.exe, TacAuthPackage.dll, TacSubAuth.dll
echo (TacProvider.lib is just the import library; you don't deploy it.)
echo (The two LSA DLLs are SKELETONS that run in LSA - VM with snapshot only.)
goto :eof

:fail
echo.
echo BUILD FAILED - see the compiler errors above.
exit /b 1
