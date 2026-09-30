cmake_minimum_required(VERSION 3.20)
project(TacProvider CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_definitions(UNICODE _UNICODE)

# Static C++ runtime (/MT): the target machine needs no VC++ Redistributable.
# Without this, LogonUI silently fails to load the DLL on a clean VM.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# --- the credential provider + filter DLL ---
add_library(TacProvider SHARED
    dll.cpp
    CTacProvider.cpp
    CTacCredential.cpp
    CTacFilter.cpp
    helpers.cpp
    totp.cpp
    store.cpp
    verify.cpp
    eventlog.cpp)

target_link_libraries(TacProvider PRIVATE
    bcrypt crypt32 advapi32 secur32 shlwapi ole32 uuid gdi32 user32 wtsapi32)

# apply the module-definition file (the COM exports)
set_target_properties(TacProvider PROPERTIES
    LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/TacProvider.def\"")

# --- the enrollment console tool ---
add_executable(enroll
    enroll.cpp
    totp.cpp
    store.cpp)

target_link_libraries(enroll PRIVATE
    bcrypt crypt32 advapi32)

# ---------------------------------------------------------------------
# Build (from a normal PowerShell/cmd, CMake must be installed):
#   cmake -B build -A x64
#   cmake --build build --config Release
# Outputs land in build\Release\TacProvider.dll and build\Release\enroll.exe
# ---------------------------------------------------------------------
