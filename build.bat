@echo off
REM =====================================================================
REM  Build TacProvider.dll and enroll.exe in one shot.
REM
REM  Run this from the "x64 Native Tools Command Prompt" of your Visual
REM  Studio / Build Tools version (Start menu -> Visual Studio folder). That shell puts
REM  cl.exe and the Windows SDK on your PATH automatically.
REM
REM  Usage:   build.bat
REM  Output:  TacProvider.dll  and  enroll.exe  in this folder.
REM  /MT links the C++ runtime statically, so the target machine needs
REM  no Visual C++ Redistributable.
REM =====================================================================

setlocal
cd /d "%~dp0"

echo.
echo === Building TacProvider.dll (credential provider + filter) ===
cl /nologo /LD /MT /EHsc /std:c++17 /W3 /DUNICODE /D_UNICODE ^
   dll.cpp CTacProvider.cpp CTacCredential.cpp CTacFilter.cpp ^
   helpers.cpp totp.cpp store.cpp verify.cpp eventlog.cpp ^
   /Fe:TacProvider.dll ^
   /link /DEF:TacProvider.def ^
   bcrypt.lib crypt32.lib advapi32.lib secur32.lib shlwapi.lib ole32.lib uuid.lib gdi32.lib user32.lib wtsapi32.lib
if errorlevel 1 goto :fail

echo.
echo === Building enroll.exe (enrollment tool) ===
cl /nologo /MT /EHsc /std:c++17 /W3 /DUNICODE /D_UNICODE ^
   enroll.cpp totp.cpp store.cpp ^
   /Fe:enroll.exe ^
   /link bcrypt.lib crypt32.lib advapi32.lib
if errorlevel 1 goto :fail

echo.
echo === Done. Cleaning up intermediate files ===
del /q *.obj *.exp 2>nul

echo.
echo Built: TacProvider.dll  and  enroll.exe
echo (TacProvider.lib is just the import library; you don't deploy it.)
goto :eof

:fail
echo.
echo BUILD FAILED - see the compiler errors above.
exit /b 1
