#!/usr/bin/env pwsh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 7.2

<#
.SYNOPSIS
    Builds the isolated Windows 11 ARM64 slice of TotalDrop (Rust bridge +
    native ARM64 Explorer COM server + WinUI 3 .NET 9 Native AOT executable +
    arm64 MSIX package) on GitHub's `windows-11-arm` runner, and optionally
    bundles `x64` + `arm64` into a single `.msixbundle` for Microsoft Store
    Partner Center submission (ADR 0016, #86).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Version = "0.2.0.0",

    [Parameter()]
    [switch]$CreateStoreBundle,

    [Parameter()]
    [switch]$SignEphemeralTestCert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$StagingDir = Join-Path $RepoRoot "dist\staging-arm64"
$OutMsix = Join-Path $RepoRoot "dist\TotalDrop_${Version}_arm64.msix"
$X64Msix = Join-Path $RepoRoot "dist\TotalDrop_${Version}_x64.msix"
$BundleInputDir = Join-Path $RepoRoot "dist\bundle-input"
$OutBundle = Join-Path $RepoRoot "dist\TotalDrop_${Version}_x64_arm64.msixbundle"

Write-Host "==> [arm64 1/5] Building Rust totaldrop-windows-bridge (aarch64-pc-windows-msvc)..."
Push-Location $RepoRoot
try {
    $env:RUSTFLAGS = "-D warnings"
    cargo build `
        --config (Join-Path $ScriptDir "cargo-config.toml") `
        --target aarch64-pc-windows-msvc `
        -p totaldrop-windows-bridge `
        --release `
        --locked
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build (aarch64-pc-windows-msvc) failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "==> [arm64 2/5] Publishing WinUI 3 shell with .NET 9 Native AOT (win-arm64)..."
$PublishDir = Join-Path $RepoRoot "dist\publish-win-arm64"
dotnet publish (Join-Path $RepoRoot "ui-winui3-fluent2\TotalDrop.WinUI.csproj") `
    -r win-arm64 `
    -c Release `
    -p:Platform=ARM64 `
    -p:PublishAot=true `
    -p:WindowsAppSDKSelfContained=false `
    -o $PublishDir
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish (win-arm64 Native AOT) failed with exit code $LASTEXITCODE"
}

Write-Host "==> [arm64 3/5] Staging arm64 MSIX layout..."
if (Test-Path $StagingDir) {
    Remove-Item -Recurse -Force $StagingDir
}
New-Item -ItemType Directory -Path $StagingDir | Out-Null
Copy-Item -Path (Join-Path $PublishDir "*") -Destination $StagingDir -Recurse -Force
Copy-Item `
    -Path (Join-Path $ScriptDir "Package.arm64.appxmanifest") `
    -Destination (Join-Path $StagingDir "AppxManifest.xml") `
    -Force

Write-Host "==> [arm64 4/5] Packing TotalDrop_${Version}_arm64.msix with makeappx.exe..."
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutMsix) | Out-Null
makeappx.exe pack /o /nv /d $StagingDir /p $OutMsix
if ($LASTEXITCODE -ne 0) {
    throw "makeappx.exe pack (arm64) failed with exit code $LASTEXITCODE"
}

if ($CreateStoreBundle) {
    Write-Host "==> [arm64 5/5] Bundling x64 + arm64 MSIX slices into $OutBundle..."
    if (-not (Test-Path $X64Msix)) {
        throw "x64 MSIX slice not found at $X64Msix. Run target-x86_64/build-x64.ps1 first."
    }
    if (Test-Path $BundleInputDir) {
        Remove-Item -Recurse -Force $BundleInputDir
    }
    New-Item -ItemType Directory -Path $BundleInputDir | Out-Null
    Copy-Item -Path $X64Msix -Destination $BundleInputDir -Force
    Copy-Item -Path $OutMsix -Destination $BundleInputDir -Force

    makeappx.exe bundle /o /bv $Version /d $BundleInputDir /p $OutBundle
    if ($LASTEXITCODE -ne 0) {
        throw "makeappx.exe bundle failed with exit code $LASTEXITCODE"
    }
    Write-Host "==> Built multi-arch Store bundle: $OutBundle"
}

if ($SignEphemeralTestCert) {
    $TargetArtifact = if ($CreateStoreBundle) { $OutBundle } else { $OutMsix }
    Write-Host "==> Signing CI test artifact with ephemeral self-signed certificate (not distributed, ADR 0016)..."
    $Cert = New-SelfSignedCertificate `
        -Type Custom `
        -Subject "CN=TotalDrop" `
        -KeyUsage DigitalSignature `
        -FriendlyName "TotalDrop Ephemeral CI Test Cert" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
    signtool.exe sign /fd SHA256 /sha1 $Cert.Thumbprint $TargetArtifact
    if ($LASTEXITCODE -ne 0) {
        throw "signtool.exe failed with exit code $LASTEXITCODE"
    }
}

Write-Host "==> Built arm64 MSIX: $OutMsix"
