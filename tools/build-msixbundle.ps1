#!/usr/bin/env pwsh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 7.2

<#
.SYNOPSIS
    Merges pre-built x64 and arm64 MSIX slices into a unified Microsoft Store
    .msixbundle (strict makeappx.exe bundle, zero /nv), wraps .msixbundle and
    .appxsym debug symbol archives into a deterministic .msixupload archive,
    validates via tools/verify-msix-artifact.py, and emits LF SHA256SUMS
    (ADR 0016, ADR 0020).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$X64Msix,

    [Parameter(Mandatory = $true)]
    [string]$Arm64Msix,

    [Parameter()]
    [string]$X64Symbols = "",

    [Parameter()]
    [string]$Arm64Symbols = "",

    [Parameter()]
    [string]$OutputDir = "",

    [Parameter()]
    [switch]$StoreMode,

    [Parameter()]
    [switch]$AllowTestIdentity,

    [Parameter()]
    [switch]$SkipUploadPackage,

    [Parameter()]
    [switch]$SkipVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-SourceDateEpoch {
    $raw = [System.Environment]::GetEnvironmentVariable("SOURCE_DATE_EPOCH")
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [int64]1760000000
    }
    [int64]$parsed = 0
    if (-not [int64]::TryParse($raw.Trim(), [ref]$parsed) -or $parsed -lt 315532800) {
        throw "Invalid SOURCE_DATE_EPOCH '$raw'. Expected integer UNIX seconds >= 315532800 (1980-01-01T00:00:00Z)."
    }
    return $parsed
}

function Assert-MsixVersionQuad {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter()]
        [switch]$RequireStoreRules
    )

    if ($Value -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw "Invalid bundle -Version '$Value'. Expected four-part numeric version (Major.Minor.Build.Revision)."
    }
    $parts = $Value.Split('.')
    $nums = @()
    foreach ($part in $parts) {
        if ($part.Length -gt 1 -and $part.StartsWith('0')) {
            throw "Invalid bundle -Version '$Value': leading zeros are not permitted in version component '$part'."
        }
        [int]$num = 0
        if (-not [int]::TryParse($part, [ref]$num) -or $num -lt 0 -or $num -gt 65535) {
            throw "Invalid bundle -Version '$Value': each component must be in 0..65535 (got '$part')."
        }
        $nums += $num
    }
    if ($RequireStoreRules) {
        if ($nums[0] -lt 1) {
            throw "Invalid Store bundle -Version '$Value': Microsoft Store requires Major >= 1 (1..65535)."
        }
        if ($nums[3] -ne 0) {
            throw "Invalid Store bundle -Version '$Value': Microsoft Store requires Revision == 0."
        }
    }
}

function Assert-ZipMagic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label not found: $Path"
    }
    $fullPath = (Resolve-Path -LiteralPath $Path).Path
    $info = Get-Item -LiteralPath $fullPath
    if ($info.Length -lt 4) {
        throw "$Label is truncated (< 4 bytes): $fullPath"
    }
    $buf = [byte[]]::new(4)
    $fs = [System.IO.File]::OpenRead($fullPath)
    try {
        $read = $fs.Read($buf, 0, 4)
        if ($read -ne 4 -or $buf[0] -ne 0x50 -or $buf[1] -ne 0x4B -or $buf[2] -ne 0x03 -or $buf[3] -ne 0x04) {
            throw "$Label is not a valid ZIP/OPC archive (expected PK\x03\x04 magic): $fullPath"
        }
    }
    finally {
        $fs.Dispose()
    }
}

function Assert-AppxSymArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    Assert-ZipMagic -Path $Path -Label $Label
    $fullPath = (Resolve-Path -LiteralPath $Path).Path
    Add-Type -AssemblyName System.IO.Compression
    $fs = [System.IO.File]::OpenRead($fullPath)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            $pdbCount = 0
            $forbiddenExts = @(".pfx", ".p12", ".cer", ".snk", ".key", ".pem", ".msix", ".appx", ".exe", ".dll")
            foreach ($entry in $zip.Entries) {
                $name = $entry.FullName
                if ([string]::IsNullOrWhiteSpace($name) -or $name.EndsWith("/")) {
                    continue
                }
                $lower = $name.ToLowerInvariant()
                foreach ($badExt in $forbiddenExts) {
                    if ($lower.EndsWith($badExt)) {
                        throw "$Label contains forbidden entry '$name'."
                    }
                }
                if (-not $lower.EndsWith(".pdb")) {
                    throw "$Label contains non-PDB entry '$name'."
                }
                if ($entry.Length -le 0) {
                    throw "$Label contains empty PDB entry '$name'."
                }
                $pdbCount++
            }
            if ($pdbCount -lt 1) {
                throw "$Label contains zero .pdb symbol entries."
            }
        }
        finally {
            $zip.Dispose()
        }
    }
    finally {
        $fs.Dispose()
    }
}

function Resolve-WindowsKitTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter()]
        [string]$PreferredArch = "x64"
    )

    $archOrder = if ($PreferredArch -eq "arm64") { @("arm64", "x64") } else { @("x64", "arm64") }

    $kitBinRoots = [System.Collections.Generic.List[string]]::new()
    $winSdkDir = [System.Environment]::GetEnvironmentVariable("WindowsSdkDir")
    if (-not [string]::IsNullOrWhiteSpace($winSdkDir)) {
        $kitBinRoots.Add((Join-Path $winSdkDir "bin"))
    }
    foreach ($pfVar in @("ProgramFiles(x86)", "ProgramFiles")) {
        $pfRoot = [System.Environment]::GetEnvironmentVariable($pfVar)
        if (-not [string]::IsNullOrWhiteSpace($pfRoot)) {
            $kitBinRoots.Add((Join-Path $pfRoot "Windows Kits\10\bin"))
        }
    }

    foreach ($kitsBin in $kitBinRoots) {
        if (-not (Test-Path -LiteralPath $kitsBin)) {
            continue
        }
        $versionDirs = @(Get-ChildItem -LiteralPath $kitsBin -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version]$_.Name } -Descending)
        foreach ($vDir in $versionDirs) {
            foreach ($arch in $archOrder) {
                $candidate = Join-Path $vDir.FullName "$arch\$ToolName"
                if (Test-Path -LiteralPath $candidate) {
                    return $candidate
                }
            }
        }
    }

    $nugetEnv = [System.Environment]::GetEnvironmentVariable("NUGET_PACKAGES")
    $userProfileEnv = [System.Environment]::GetEnvironmentVariable("USERPROFILE")
    $nugetRoot = ""
    if (-not [string]::IsNullOrWhiteSpace($nugetEnv)) {
        $nugetRoot = $nugetEnv
    } elseif (-not [string]::IsNullOrWhiteSpace($userProfileEnv)) {
        $nugetRoot = Join-Path $userProfileEnv ".nuget\packages"
    }
    if (-not [string]::IsNullOrWhiteSpace($nugetRoot)) {
        $btRoot = Join-Path $nugetRoot "microsoft.windows.sdk.buildtools"
        if (Test-Path -LiteralPath $btRoot) {
            $pkgDirs = @(Get-ChildItem -LiteralPath $btRoot -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending)
            foreach ($pkgDir in $pkgDirs) {
                $binRoot = Join-Path $pkgDir.FullName "bin"
                if (-not (Test-Path -LiteralPath $binRoot)) { continue }
                $sdkDirs = @(Get-ChildItem -LiteralPath $binRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
                    Sort-Object { [version]$_.Name } -Descending)
                foreach ($sdkDir in $sdkDirs) {
                    foreach ($arch in $archOrder) {
                        $candidate = Join-Path $sdkDir.FullName "$arch\$ToolName"
                        if (Test-Path -LiteralPath $candidate) {
                            return $candidate
                        }
                    }
                }
            }
        }
    }

    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    throw "Required Windows SDK tool '$ToolName' not found in Windows Kits 10, NuGet BuildTools, or PATH."
}

function Resolve-PythonCommand {
    $candidates = @(
        @{ Exe = "python3"; PrefixArgs = @() },
        @{ Exe = "python";  PrefixArgs = @() },
        @{ Exe = "py";      PrefixArgs = @("-3") }
    )

    foreach ($cand in $candidates) {
        $cmds = @(Get-Command $cand.Exe -All -CommandType Application -ErrorAction SilentlyContinue)
        foreach ($cmd in $cmds) {
            $src = [string]$cmd.Source
            if ([string]::IsNullOrWhiteSpace($src)) {
                continue
            }
            # Skip Windows 11 Microsoft Store App Execution Alias stubs (%LOCALAPPDATA%\Microsoft\WindowsApps\python*.exe).
            if ($src -match '(?i)[\\/]Microsoft[\\/]WindowsApps[\\/]python[^\\/]*\.exe$') {
                continue
            }
            $probeArgs = @($cand.PrefixArgs) + @(
                "-c",
                "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}'); raise SystemExit(0 if sys.version_info >= (3, 10) else 2)"
            )
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                $verOut = (& $src @probeArgs 2>$null | Out-String).Trim()
                $probeExit = $LASTEXITCODE
            }
            catch {
                $probeExit = -1
                $verOut = ""
            }
            finally {
                $ErrorActionPreference = $prevEap
            }
            if ($probeExit -eq 0) {
                return [PSCustomObject]@{
                    Executable = $src
                    PrefixArgs = @($cand.PrefixArgs)
                    Version    = $verOut
                }
            }
        }
    }

    throw "Python >= 3.10 is required to run tools/verify-msix-artifact.py (checked python3, python, and py -3, skipping WindowsApps Store alias stubs)."
}

function New-DeterministicZipArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$EntryMap,

        [Parameter(Mandatory = $true)]
        [int64]$EpochSeconds
    )

    Add-Type -AssemblyName System.IO.Compression
    if (Test-Path -LiteralPath $DestinationPath) {
        Remove-Item -LiteralPath $DestinationPath -Force
    }
    $sortedNames = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $EntryMap.Keys) {
        $sortedNames.Add([string]$key)
    }
    $sortedNames.Sort([System.StringComparer]::Ordinal)

    # Use UTC DateTimeOffset directly so ZIP DOS timestamps are timezone-independent.
    $zipTimestamp = [System.DateTimeOffset]::FromUnixTimeSeconds($EpochSeconds)
    $fs = [System.IO.File]::Open($DestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($entryName in $sortedNames) {
                $sourceFile = (Resolve-Path -LiteralPath ([string]$EntryMap[$entryName])).Path
                $entry = $archive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $zipTimestamp
                $entry.ExternalAttributes = 0
                $srcStream = [System.IO.File]::OpenRead($sourceFile)
                try {
                    $dstStream = $entry.Open()
                    try {
                        $srcStream.CopyTo($dstStream)
                    }
                    finally {
                        $dstStream.Dispose()
                    }
                }
                finally {
                    $srcStream.Dispose()
                }
            }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $fs.Dispose()
    }
    [System.IO.File]::SetLastWriteTimeUtc($DestinationPath, $zipTimestamp.UtcDateTime)
}

$SourceDateEpoch = Resolve-SourceDateEpoch
$EpochUtc = [System.DateTimeOffset]::FromUnixTimeSeconds($SourceDateEpoch).UtcDateTime

Assert-MsixVersionQuad -Value $Version -RequireStoreRules:$StoreMode

$ScriptDir = $PSScriptRoot
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path

Assert-ZipMagic -Path $X64Msix -Label "x64 MSIX"
Assert-ZipMagic -Path $Arm64Msix -Label "arm64 MSIX"
$ResolvedX64Msix = (Resolve-Path -LiteralPath $X64Msix).Path
$ResolvedArm64Msix = (Resolve-Path -LiteralPath $Arm64Msix).Path
if ($ResolvedX64Msix.Equals($ResolvedArm64Msix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "X64Msix and Arm64Msix must point to two distinct architecture MSIX archives."
}

$ResolvedOutDir = if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    Join-Path $RepoRoot "dist\store"
} else {
    $OutputDir
}
New-Item -ItemType Directory -Force -Path $ResolvedOutDir | Out-Null
$ResolvedOutDir = (Resolve-Path -LiteralPath $ResolvedOutDir).Path

$WorkDir = Join-Path $RepoRoot "dist\work-bundle"
$BundleInputDir = Join-Path $WorkDir "bundle-input"
if (Test-Path -LiteralPath $BundleInputDir) {
    Remove-Item -LiteralPath $BundleInputDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $BundleInputDir | Out-Null

$StagedX64 = Join-Path $BundleInputDir "TotalDrop_${Version}_x64.msix"
$StagedArm64 = Join-Path $BundleInputDir "TotalDrop_${Version}_arm64.msix"
Copy-Item -LiteralPath $ResolvedX64Msix -Destination $StagedX64 -Force
Copy-Item -LiteralPath $ResolvedArm64Msix -Destination $StagedArm64 -Force
[System.IO.File]::SetLastWriteTimeUtc($StagedX64, $EpochUtc)
[System.IO.File]::SetLastWriteTimeUtc($StagedArm64, $EpochUtc)

$MakeAppxExe = Resolve-WindowsKitTool -ToolName "makeappx.exe" -PreferredArch "x64"
Write-Host "==> [bundle 1/3] Packing unified x64+arm64 bundle with strict makeappx.exe (no /nv)..."
Write-Host "    MakeAppx: $MakeAppxExe"

$OutBundleName = "TotalDrop-${Version}.msixbundle"
$OutBundle = Join-Path $ResolvedOutDir $OutBundleName
& $MakeAppxExe bundle /o /bv $Version /d $BundleInputDir /p $OutBundle
if ($LASTEXITCODE -ne 0) {
    throw "makeappx.exe bundle failed with exit code $LASTEXITCODE"
}
[System.IO.File]::SetLastWriteTimeUtc($OutBundle, $EpochUtc)

$OutUploadName = "TotalDrop-${Version}.msixupload"
$OutUpload = Join-Path $ResolvedOutDir $OutUploadName
if (-not $SkipUploadPackage) {
    Write-Host "==> [bundle 2/3] Packing deterministic Partner Center archive $OutUploadName..."
    if ([string]::IsNullOrWhiteSpace($X64Symbols) -or [string]::IsNullOrWhiteSpace($Arm64Symbols)) {
        throw "Both -X64Symbols and -Arm64Symbols (.appxsym archives) are required to build .msixupload (or pass -SkipUploadPackage)."
    }
    Assert-AppxSymArchive -Path $X64Symbols -Label "x64 symbols archive"
    Assert-AppxSymArchive -Path $Arm64Symbols -Label "arm64 symbols archive"
    $ResolvedX64Sym = (Resolve-Path -LiteralPath $X64Symbols).Path
    $ResolvedArm64Sym = (Resolve-Path -LiteralPath $Arm64Symbols).Path

    # Wrap ONLY the unified .msixbundle + per-arch .appxsym archives (zero bare .msix, zero signing keys).
    $uploadEntries = @{
        $OutBundleName                   = $OutBundle
        "TotalDrop_${Version}_arm64.appxsym" = $ResolvedArm64Sym
        "TotalDrop_${Version}_x64.appxsym"   = $ResolvedX64Sym
    }
    New-DeterministicZipArchive -DestinationPath $OutUpload -EntryMap $uploadEntries -EpochSeconds $SourceDateEpoch
} else {
    Write-Host "==> [bundle 2/3] Skipping .msixupload assembly (-SkipUploadPackage)."
}

if (-not $SkipVerify) {
    Write-Host "==> [bundle 3/3] Deep-verifying unified bundle & upload package via tools/verify-msix-artifact.py..."
    $verifyArgs = @(
        (Join-Path $RepoRoot "tools\verify-msix-artifact.py"),
        "--bundle", $OutBundle,
        "--expected-version", $Version
    )
    if (-not $SkipUploadPackage) {
        $verifyArgs += @("--msixupload", $OutUpload)
    }
    if ($StoreMode) {
        $verifyArgs += "--store-mode"
        if ($AllowTestIdentity) {
            $verifyArgs += "--allow-test-identity"
        }
    }
    $pythonCmd = Resolve-PythonCommand
    Write-Host "    Python:   $($pythonCmd.Executable) ($($pythonCmd.Version))"
    $allVerifyArgs = @($pythonCmd.PrefixArgs) + $verifyArgs
    & $pythonCmd.Executable @allVerifyArgs
    if ($LASTEXITCODE -ne 0) {
        throw "tools/verify-msix-artifact.py failed with exit code $LASTEXITCODE"
    }
}

$ArtifactsToHash = [System.Collections.Generic.List[string]]::new()
$ArtifactsToHash.Add($OutBundleName)
if (-not $SkipUploadPackage) {
    $ArtifactsToHash.Add($OutUploadName)
}
$ArtifactsToHash.Sort([System.StringComparer]::Ordinal)

$ChecksumLines = [System.Collections.Generic.List[string]]::new()
foreach ($artName in $ArtifactsToHash) {
    $artPath = Join-Path $ResolvedOutDir $artName
    $hashHex = (Get-FileHash -Algorithm SHA256 -LiteralPath $artPath).Hash.ToLowerInvariant()
    $ChecksumLines.Add("$hashHex  $artName")
}
$ChecksumsPath = Join-Path $ResolvedOutDir "SHA256SUMS"
[System.IO.File]::WriteAllText(
    $ChecksumsPath,
    ($ChecksumLines -join "`n") + "`n",
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "==> Built Store bundle: $OutBundle"
if (-not $SkipUploadPackage) {
    Write-Host "==> Built Partner Center upload package: $OutUpload"
}
Write-Host "==> Wrote checksums: $ChecksumsPath"
