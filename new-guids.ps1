# Creates new CLSIDs for the provider and the filter and writes them into
# guid.h and all .reg files in this folder.
#
# Run it once in the project folder, then rebuild with build.bat.
# If an older version is still registered, run unregister.reg BEFORE this
# script. A copy with the old GUIDs is kept as unregister-old.reg anyway.

$ErrorActionPreference = 'Stop'
$root     = $PSScriptRoot
$guidFile = Join-Path $root 'guid.h'
$regFiles = Get-ChildItem -Path $root -Filter '*.reg' | Where-Object { $_.Name -ne 'unregister-old.reg' }

# The first two {...} in guid.h are the current provider and filter GUIDs.
$found = [regex]::Matches((Get-Content $guidFile -Raw), '\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}')
if ($found.Count -lt 2) { throw 'Could not find the current GUIDs in guid.h.' }
$oldProvider = $found[0].Groups[1].Value.ToUpper()
$oldFilter   = $found[1].Groups[1].Value.ToUpper()

$newProvider = [guid]::NewGuid().ToString().ToUpper()
$newFilter   = [guid]::NewGuid().ToString().ToUpper()

# {B1E7C9A0-2F4D-4C6B-9A11-0000C0FFEE01} becomes
# 0xb1e7c9a0, 0x2f4d, 0x4c6b, 0x9a, 0x11, 0x00, 0x00, 0xc0, 0xff, 0xee, 0x01
function Get-DefineGuid([string]$name, [string]$guid)
{
    $hex   = $guid.Replace('-', '').ToLower()
    $bytes = @()
    for ($i = 16; $i -lt 32; $i += 2) { $bytes += '0x' + $hex.Substring($i, 2) }
    $parts = @('0x' + $hex.Substring(0, 8), '0x' + $hex.Substring(8, 4), '0x' + $hex.Substring(12, 4)) + $bytes
    return "DEFINE_GUID($name,`r`n    " + ($parts -join ', ') + ');'
}

# Keep an unregister file with the old GUIDs, in case they are still registered.
$unregister = Join-Path $root 'unregister.reg'
if (Test-Path $unregister) { Copy-Item $unregister (Join-Path $root 'unregister-old.reg') -Force }

$lines = @(
    '#pragma once'
    '#include <guiddef.h>'
    ''
    '// Created by new-guids.ps1. Keep them in sync with the .reg files.'
    '// dll.cpp includes initguid.h before this header, so the GUIDs are defined'
    '// there and only declared everywhere else.'
    ''
    "// {$newProvider}"
    (Get-DefineGuid 'CLSID_CTacProvider' $newProvider)
    ''
    "// {$newFilter}"
    (Get-DefineGuid 'CLSID_CTacFilter' $newFilter)
)
Set-Content -Path $guidFile -Value ($lines -join "`r`n") -Encoding Ascii

foreach ($file in $regFiles)
{
    $text = Get-Content $file.FullName -Raw
    $text = $text -ireplace [regex]::Escape($oldProvider), $newProvider
    $text = $text -ireplace [regex]::Escape($oldFilter),   $newFilter
    Set-Content -Path $file.FullName -Value $text -Encoding Ascii -NoNewline
}

Write-Host ''
Write-Host "Provider: {$oldProvider} -> {$newProvider}"
Write-Host "Filter:   {$oldFilter} -> {$newFilter}"
Write-Host ''
Write-Host 'Updated guid.h and:' ($regFiles.Name -join ', ')
Write-Host 'Now rebuild with build.bat and register again.'
