cmake_minimum_required(VERSION 3.20)
project(TacProvider CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_definitions(UNICODE _UNICODE)

# Static C++ runtime (/MT): the target machine needs no VC++ Redistributable.
# Without this, LogonUI silently fails to load the DLL on a clean VM.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# These binaries run in LogonUI and lsass: Control Flow Guard and SDL checks, warning level 4.
if(MSVC)
    add_compile_options(/guard:cf /sdl /W4)
    add_link_options(/guard:cf)
endif()

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
    statelock.cpp
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
    store.cpp
    statelock.cpp)

target_link_libraries(enroll PRIVATE
    bcrypt crypt32 advapi32)

# --- the LSA authentication package (SKELETON) ---
# Runs inside lsass.exe. A bug here can leave the machine unbootable.
# Load only in a throwaway VM with a snapshot. See ap.h and the article.
add_library(TacAuthPackage SHARED
    ap.cpp
    store.cpp
    totp.cpp)

target_link_libraries(TacAuthPackage PRIVATE
    advapi32 crypt32 bcrypt)

set_target_properties(TacAuthPackage PROPERTIES
    LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/TacAuthPackage.def\"")

# --- the MSV1_0 sub-authentication package (SKELETON) ---
# Called by MSV1_0 during its logon processing; MSV1_0 keeps the token work.
# Same warnings as above: lsass.exe, VM with snapshot only.
add_library(TacSubAuth SHARED
    subauth.cpp
    store.cpp
    totp.cpp)

target_link_libraries(TacSubAuth PRIVATE
    advapi32 crypt32 bcrypt)

set_target_properties(TacSubAuth PROPERTIES
    LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/TacSubAuth.def\"")

# ---------------------------------------------------------------------
# Build (from a normal PowerShell/cmd, CMake must be installed):
#   cmake -B build -A x64
#   cmake --build build --config Release
# Outputs land in build\Release\
# ---------------------------------------------------------------------
