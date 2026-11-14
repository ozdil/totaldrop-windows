#!/usr/bin/env pwsh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 7.2

<#
.SYNOPSIS
    Builds the isolated Windows 11 x86_64 slice of TotalDrop (Rust bridge +
    native x64 Explorer COM server + WinUI 3 .NET 9 Native AOT executable +
    x64 MSIX package) on GitHub's `windows-2025` runner (ADR 0016).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Version = "0.2.0.0",

    [Parameter()]
    [switch]$SignEphemeralTestCert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$StagingDir = Join-Path $RepoRoot "dist\staging-x64"
$OutMsix = Join-Path $RepoRoot "dist\TotalDrop_${Version}_x64.msix"

Write-Host "==> [x64 1/4] Building Rust totaldrop-windows-bridge (x86_64-pc-windows-msvc)..."
Push-Location $RepoRoot
try {
    $env:RUSTFLAGS = "-D warnings"
    cargo build `
        --config (Join-Path $ScriptDir "cargo-config.toml") `
        --target x86_64-pc-windows-msvc `
        -p totaldrop-windows-bridge `
        --release `
        --locked
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build (x86_64-pc-windows-msvc) failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "==> [x64 2/4] Publishing WinUI 3 shell with .NET 9 Native AOT (win-x64)..."
$PublishDir = Join-Path $RepoRoot "dist\publish-win-x64"
dotnet publish (Join-Path $RepoRoot "ui-winui3-fluent2\TotalDrop.WinUI.csproj") `
    -r win-x64 `
    -c Release `
    -p:Platform=x64 `
    -p:PublishAot=true `
    -p:WindowsAppSDKSelfContained=false `
    -o $PublishDir
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish (win-x64 Native AOT) failed with exit code $LASTEXITCODE"
}

Write-Host "==> [x64 3/4] Staging x64 MSIX layout..."
if (Test-Path $StagingDir) {
    Remove-Item -Recurse -Force $StagingDir
}
New-Item -ItemType Directory -Path $StagingDir | Out-Null
Copy-Item -Path (Join-Path $PublishDir "*") -Destination $StagingDir -Recurse -Force
Copy-Item `
    -Path (Join-Path $ScriptDir "Package.x64.appxmanifest") `
    -Destination (Join-Path $StagingDir "AppxManifest.xml") `
    -Force

Write-Host "==> [x64 4/4] Packing TotalDrop_${Version}_x64.msix with makeappx.exe..."
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutMsix) | Out-Null
makeappx.exe pack /o /nv /d $StagingDir /p $OutMsix
if ($LASTEXITCODE -ne 0) {
    throw "makeappx.exe pack (x64) failed with exit code $LASTEXITCODE"
}

if ($SignEphemeralTestCert) {
    Write-Host "==> Signing x64 CI test MSIX with ephemeral self-signed certificate (not distributed, ADR 0016)..."
    $Cert = New-SelfSignedCertificate `
        -Type Custom `
        -Subject "CN=TotalDrop" `
        -KeyUsage DigitalSignature `
        -FriendlyName "TotalDrop Ephemeral CI Test Cert" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
    signtool.exe sign /fd SHA256 /sha1 $Cert.Thumbprint $OutMsix
    if ($LASTEXITCODE -ne 0) {
        throw "signtool.exe failed with exit code $LASTEXITCODE"
    }
}

Write-Host "==> Built x64 MSIX: $OutMsix"
