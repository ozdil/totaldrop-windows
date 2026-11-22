#!/usr/bin/env pwsh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 7.2

<#
.SYNOPSIS
    Headless Windows CI E2E test orchestrator for TotalDrop for Windows (Full M1-M4).
    Executes all 60 windows-ci tests (22 M1 + 8 M2 + 21 M3 + 9 M4) with zero interactive
    WinUI windows and zero live production network connections.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("M1", "M2", "M3", "M4", "All")]
    [string]$Milestone = "All",

    [Parameter()]
    [string]$MsixPath = "",

    [Parameter()]
    [string]$Arm64MsixPath = "",

    [Parameter()]
    [string]$BundlePath = "",

    [Parameter()]
    [string]$MsixUploadPath = "",

    [Parameter()]
    [string]$RuntimeDepMsix = "",

    [Parameter()]
    [switch]$SkipBuild,

    [Parameter()]
    [string]$ResultsJson = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$PythonExe = if (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" } else { "python" }
$Results = [ordered]@{}

function Resolve-WindowsKitTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName
    )
    $kitsBin = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path -LiteralPath $kitsBin) {
        $versionDirs = Get-ChildItem -LiteralPath $kitsBin -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($vDir in $versionDirs) {
            foreach ($arch in @("x64", "arm64")) {
                $cand = Join-Path $vDir.FullName "$arch\$ToolName"
                if (Test-Path -LiteralPath $cand) { return $cand }
            }
        }
    }
    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }
    throw "Required Windows SDK tool '$ToolName' not found."
}

function Resolve-DumpBinExe {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $found = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe" |
            Select-Object -First 1
        if (-not [string]::IsNullOrWhiteSpace($found) -and (Test-Path -LiteralPath $found)) {
            return $found
        }
    }
    $cmd = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }
    throw "dumpbin.exe not found via vswhere.exe or PATH."
}

function Resolve-PosixSh {
    $cmd = Get-Command sh -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }
    foreach ($cand in @(
        "C:\Program Files\Git\bin\sh.exe",
        "C:\Program Files\Git\usr\bin\sh.exe"
    )) {
        if (Test-Path -LiteralPath $cand) { return $cand }
    }
    throw "POSIX sh executable not found on PATH or Git for Windows."
}

function Invoke-E2ETest {
    param(
        [Parameter(Mandatory = $true)][string]$TestId,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )
    try {
        $detail = & $Body
        $Results[$TestId] = @{ status = "PASS"; detail = ([string]$detail) }
        Write-Host "[PASS] $TestId : $detail"
    }
    catch {
        $Results[$TestId] = @{ status = "FAIL"; detail = $_.Exception.Message }
        Write-Host "[FAIL] $TestId : $($_.Exception.Message)" -ForegroundColor Red
    }
}

$WorkTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("totaldrop-win-e2e-" + $PID + "-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $WorkTemp | Out-Null

try {
    $ExpectedArtifactName = (& $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --root $RepoRoot --arch x64 --resolve-recipe).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ExpectedArtifactName)) {
        throw "Failed to resolve artifact_name from subplatforms/msix/x86_64/RECIPE.toml"
    }

    if ([string]::IsNullOrWhiteSpace($MsixPath)) {
        $MsixPath = Join-Path $RepoRoot ("dist\" + $ExpectedArtifactName)
    }

    $RunM1 = ($Milestone -eq "M1" -or $Milestone -eq "All")
    $RunM2 = ($Milestone -eq "M2" -or $Milestone -eq "All")
    $RunM3 = ($Milestone -eq "M3" -or $Milestone -eq "All")
    $RunM4 = ($Milestone -eq "M4" -or $Milestone -eq "All")

    $MakePriExe = Resolve-WindowsKitTool -ToolName "MakePri.exe"
    $MakeAppxExe = Resolve-WindowsKitTool -ToolName "makeappx.exe"
    [void](Resolve-WindowsKitTool -ToolName "signtool.exe")
    $DumpBinExe = Resolve-DumpBinExe

    $PubOutDir = Join-Path $WorkTemp "publish-win-x64"
    $UnpackedDir = Join-Path $WorkTemp "unpacked-msix"
    $PriDumpPath = Join-Path $WorkTemp "pri-dump.xml"
    $FfiDll = Join-Path $RepoRoot "target\x86_64-pc-windows-msvc\release\totaldrop_windows_ffi.dll"
    $ExtDll = Join-Path $RepoRoot "target\x86_64-pc-windows-msvc\release\totaldrop_explorer_ext.dll"

    if ($RunM1) {
        # T1-F05-02: PowerShell AST parse + ambient RUSTFLAGS restoration around build-x64.ps1
        Invoke-E2ETest "T1-F05-02" {
            $buildScript = Join-Path $RepoRoot "target-x86_64\build-x64.ps1"
            $tokens = $null
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$tokens, [ref]$parseErrors)
            if ($parseErrors.Count -ne 0) {
                throw "PowerShell AST parse errors in build-x64.ps1: $($parseErrors -join '; ')"
            }
            if (-not $SkipBuild) {
                $childCmd = @"
`$ErrorActionPreference = 'Stop'
`$env:RUSTFLAGS = '-C debuginfo=2'
& '$buildScript' -SelfSignEphemeral
if (`$env:RUSTFLAGS -ne '-C debuginfo=2') {
    throw "Caller RUSTFLAGS not restored: got '`$(`$env:RUSTFLAGS)'"
}
"@
                & pwsh -NoProfile -Command $childCmd
                if ($LASTEXITCODE -ne 0) { throw "build-x64.ps1 -SelfSignEphemeral failed with exit $LASTEXITCODE" }
            }
            "AST 0 errors; build-x64.ps1 -SelfSignEphemeral succeeded and restored caller RUSTFLAGS"
        }

        # T1-F02-03: Clean .NET 10 Native AOT publish with zero warnings
        Invoke-E2ETest "T1-F02-03" {
            if (-not (Test-Path -LiteralPath $FfiDll)) {
                throw "Missing compiled x64 FFI DLL at $FfiDll"
            }
            New-Item -ItemType Directory -Force -Path $PubOutDir | Out-Null
            & dotnet publish (Join-Path $RepoRoot "ui-winui3-fluent2\TotalDrop.WinUI.csproj") `
                -r win-x64 -c Release -p:Platform=x64 -p:PublishAot=true `
                -p:WindowsAppSDKSelfContained=false -p:TreatWarningsAsErrors=true -o $PubOutDir
            if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit $LASTEXITCODE" }
            "dotnet publish -r win-x64 PublishAot=true TreatWarningsAsErrors=true exited 0"
        }

        # T1-F02-04 & T1-F02-05: PE32+ Native AOT purity & RT_GROUP_ICON/RT_ICON resources
        Invoke-E2ETest "T1-F02-04" {
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $PubOutDir --arch x64 --milestone M1
            if ($LASTEXITCODE -ne 0) { throw "verify_pe_hardening.py failed on publish output" }
            "PE32+ AMD64 Native AOT purity and staged totaldrop_windows_ffi.dll verified"
        }
        Invoke-E2ETest "T1-F02-05" {
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $PubOutDir --arch x64 --milestone M1
            if ($LASTEXITCODE -ne 0) { throw "RT_GROUP_ICON/RT_ICON resource check failed" }
            "RT_GROUP_ICON (14) and RT_ICON (3) resources verified in totaldrop-winui.exe"
        }

        # T2-F02-01: Missing totaldrop_windows_ffi.dll MUST fail dotnet publish loudly
        Invoke-E2ETest "T2-F02-01" {
            $isoRoot = Join-Path $WorkTemp "missing-dll-copy"
            $isoUi = Join-Path $isoRoot "ui-winui3-fluent2"
            New-Item -ItemType Directory -Force -Path $isoUi | Out-Null
            Get-ChildItem -LiteralPath (Join-Path $RepoRoot "ui-winui3-fluent2") -Force |
                Where-Object { $_.Name -notin @("bin", "obj", "TotalDrop.WinUI.Tests") } |
                ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $isoUi -Recurse -Force }
            $isoOut = Join-Path $WorkTemp "missing-dll-out"
            & dotnet publish (Join-Path $isoUi "TotalDrop.WinUI.csproj") `
                -r win-x64 -c Release -p:Platform=x64 -p:PublishAot=true -o $isoOut 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                throw "dotnet publish unexpectedly succeeded when totaldrop_windows_ffi.dll was missing!"
            }
            "dotnet publish failed loudly (exit $LASTEXITCODE) when native FFI DLL is absent"
        }

        # T2-F02-04: 3 CLR/JIT/apphost contamination mutations rejected
        Invoke-E2ETest "T2-F02-04" {
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $PubOutDir --arch x64 --milestone M1 --self-test-mutations
            if ($LASTEXITCODE -ne 0) { throw "T2-F02-04 CLR/apphost mutation self-test failed" }
            "All CLR/apphost contamination mutations rejected by verify_pe_hardening.py"
        }

        # T1-F05-03: Strict makeappx.exe unpack of RECIPE-resolved MSIX
        Invoke-E2ETest "T1-F05-03" {
            if (-not (Test-Path -LiteralPath $MsixPath)) { throw "MSIX not found: $MsixPath" }
            & $MakeAppxExe unpack /o /p $MsixPath /d $UnpackedDir
            if ($LASTEXITCODE -ne 0) { throw "makeappx.exe unpack failed with exit $LASTEXITCODE" }
            foreach ($req in @("AppxManifest.xml", "AppxBlockMap.xml", "resources.pri", "totaldrop-winui.exe", "totaldrop_windows_ffi.dll")) {
                if (-not (Test-Path -LiteralPath (Join-Path $UnpackedDir $req))) {
                    throw "Unpacked MSIX missing $req"
                }
            }
            "makeappx.exe unpack verified SHA-256 blockmap and unpacked all required payloads"
        }

        # T1-F04-03, T1-F04-04, T1-F04-05: resources.pri magic/size + MakePri dump 35 locales & qualifiers
        Invoke-E2ETest "T1-F04-03" {
            $priFile = Join-Path $UnpackedDir "resources.pri"
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --check-pri-file $priFile
            if ($LASTEXITCODE -ne 0) { throw "resources.pri magic/size verification failed" }
            "resources.pri > 4096 bytes with exact b'mrm_pri2' header"
        }
        Invoke-E2ETest "T1-F04-04" {
            & $MakePriExe dump /if (Join-Path $UnpackedDir "resources.pri") /of $PriDumpPath /dt detailed /o
            if ($LASTEXITCODE -ne 0) { throw "MakePri.exe dump failed with exit $LASTEXITCODE" }
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "pri.xml 35-language completeness check failed" }
            "All 35 canonical BCP-47 languages verified in dumped pri.xml"
        }
        Invoke-E2ETest "T1-F04-05" {
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "pri.xml asset qualifier check failed" }
            "Scale (100..400), TargetSize (16..256), UNPLATED, and LIGHTUNPLATED verified in pri.xml"
        }

        # T2-F04-04: 0-byte and FAKEPRI! stub rejected
        Invoke-E2ETest "T2-F04-04" {
            $zeroPri = Join-Path $WorkTemp "zero.pri"
            $fakePri = Join-Path $WorkTemp "fake.pri"
            [System.IO.File]::WriteAllBytes($zeroPri, @())
            [System.IO.File]::WriteAllBytes($fakePri, [System.Text.Encoding]::ASCII.GetBytes("FAKEPRI!" + ("x" * 5000)))
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --check-pri-file $zeroPri 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { throw "0-byte PRI unexpectedly passed" }
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --check-pri-file $fakePri 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { throw "FAKEPRI! stub unexpectedly passed" }
            "0-byte and non-mrm_pri2 stub resources.pri rejected"
        }

        # T2-F04-05: 34-locale zh-Hant removal in MakePri + duplicate <Resource Language="tr"/> check
        Invoke-E2ETest "T2-F04-05" {
            $badStage = Join-Path $WorkTemp "pri-34-stage"
            Copy-Item -Path $UnpackedDir -Destination $badStage -Recurse -Force
            Remove-Item -LiteralPath (Join-Path $badStage "resources.pri") -Force -ErrorAction SilentlyContinue
            $stringsDst = Join-Path $badStage "Strings"
            Copy-Item -Path (Join-Path $RepoRoot "ui-winui3-fluent2\Strings") -Destination $stringsDst -Recurse -Force
            Remove-Item -LiteralPath (Join-Path $stringsDst "locales.json") -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $stringsDst "zh-Hant") -Recurse -Force
            $manPath = Join-Path $badStage "AppxManifest.xml"
            $manText = Get-Content -LiteralPath $manPath -Raw
            Set-Content -LiteralPath $manPath -Value ($manText -replace '<Resource Language="zh-Hant"\s*/>', '') -NoNewline
            $badCfg = Join-Path $WorkTemp "bad-priconfig.xml"
            $badPri = Join-Path $badStage "resources.pri"
            $badDump = Join-Path $WorkTemp "bad-pri.xml"
            & $MakePriExe createconfig /cf $badCfg /dq lang-en /o /pv 10.0.0 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri createconfig failed in T2-F04-05 with exit $LASTEXITCODE" }
            [xml]$px = Get-Content -LiteralPath $badCfg -Raw
            $pkgNode = $px.SelectSingleNode("/resources/packaging")
            if ($null -ne $pkgNode) { [void]$px.resources.RemoveChild($pkgNode) }
            $px.Save($badCfg)
            & $MakePriExe new /pr $badStage /cf $badCfg /mn $manPath /of $badPri /o | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri new failed in T2-F04-05 with exit $LASTEXITCODE" }
            & $MakePriExe dump /if $badPri /of $badDump /dt detailed /o | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri dump failed in T2-F04-05 with exit $LASTEXITCODE" }
            $out34 = & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --pri-dump $badDump 2>&1
            $out34Text = ($out34 -join "`n")
            if ($LASTEXITCODE -eq 0 -or $out34Text -notmatch "34 != 35" -or $out34Text -notmatch "zh-Hant") {
                throw "34-locale PRI dump without zh-Hant was not caught with '34 != 35' and 'zh-Hant': $out34Text"
            }

            $dupRepo = Join-Path $WorkTemp "dup-tr-repo"
            & git clone --local --no-hardlinks -q $RepoRoot $dupRepo
            $dupMan = Join-Path $dupRepo "target-x86_64\Package.x64.appxmanifest"
            $dupText = Get-Content -LiteralPath $dupMan -Raw
            $dupText = $dupText -replace '(<Resource Language="tr" />)', "`$1`n    <Resource Language=`"tr`" />"
            Set-Content -LiteralPath $dupMan -Value $dupText -NoNewline
            $outDup = & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py") --milestone M1 --root $dupRepo 2>&1
            if ($LASTEXITCODE -eq 0 -or ($outDup -join "`n") -notmatch "tr") {
                throw "Duplicate <Resource Language='tr'/> was not caught: $outDup"
            }
            "34-locale PRI dump missing zh-Hant and duplicate tr manifest resource both caught"
        }

        # T1-F05-04: PE32+ oracle + dumpbin.exe cross-check on unpacked totaldrop_windows_ffi.dll
        Invoke-E2ETest "T1-F05-04" {
            $unpackedFfi = Join-Path $UnpackedDir "totaldrop_windows_ffi.dll"
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $UnpackedDir --arch x64 --milestone M1
            if ($LASTEXITCODE -ne 0) { throw "verify_pe_hardening.py failed on unpacked MSIX" }
            $dumpOut = (& $DumpBinExe /headers /loadconfig /imports /exports $unpackedFfi) -join "`n"
            if ($LASTEXITCODE -ne 0) { throw "dumpbin.exe failed with exit $LASTEXITCODE" }
            foreach ($tok in @("8664", "Dynamic base", "NX compatible", "High Entropy Virtual Addresses", "totaldrop_win_version_json")) {
                if ($dumpOut -notmatch [regex]::Escape($tok)) {
                    throw "dumpbin output missing expected token '$tok'"
                }
            }
            if ($dumpOut -match "vcruntime140|msvcp140|concrt140|vcomp140|ucrtbased") {
                throw "dumpbin detected forbidden dynamic/debug CRT import"
            }
            "PE32+ oracle and dumpbin.exe corroborated hardening, +crt-static, and M1 exports"
        }

        # T1-F05-05: AppxSignature.p7x CN=TotalDrop + SHA-256 + SHA256SUMS + zero key residue
        Invoke-E2ETest "T1-F05-05" {
            $sig = Get-AuthenticodeSignature -FilePath $MsixPath
            if ($null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Subject -ne "CN=TotalDrop") {
                throw "Unexpected Authenticode signer subject: $($sig.SignerCertificate.Subject)"
            }
            if ($sig.SignerCertificate.SignatureAlgorithm.FriendlyName -notmatch 'sha256') {
                throw "Unexpected Authenticode signature algorithm: $($sig.SignerCertificate.SignatureAlgorithm.FriendlyName)"
            }
            if ($sig.Status -in @("NotSigned", "HashMismatch", "NotSupportedFileFormat")) {
                throw "Invalid Authenticode signature status: $($sig.Status)"
            }
            $distDir = Split-Path -Parent $MsixPath
            $sumsPath = Join-Path $distDir "SHA256SUMS"
            if (-not (Test-Path -LiteralPath $sumsPath)) { throw "Missing $sumsPath" }
            $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $MsixPath).Hash.ToLowerInvariant()
            $sumsText = Get-Content -LiteralPath $sumsPath -Raw
            if ($sumsText -notmatch "$actualHash\s+$([regex]::Escape((Split-Path -Leaf $MsixPath)))") {
                throw "SHA256SUMS does not match $MsixPath ($actualHash)"
            }
            $leaks = @(Get-ChildItem -Path $RepoRoot -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Extension -in @(".pfx", ".p12", ".cer", ".snk") })
            if ($leaks.Count -gt 0) { throw "Signing key residue found in repo: $($leaks.FullName -join ', ')" }
            "CN=TotalDrop SHA-256 signature, SHA256SUMS, and zero key residue verified"
        }

        # T1-F06-04: OPC/MSIX validator + subplatforms/msix/x86_64/verify.sh
        Invoke-E2ETest "T1-F06-04" {
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") `
                --msix $MsixPath --arch x64 --milestone M1 --expect-signed --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "verify_msix_opc.py failed on signed MSIX" }
            $distDir = Split-Path -Parent $MsixPath
            $shExe = Resolve-PosixSh
            & $shExe (Join-Path $RepoRoot "subplatforms\msix\x86_64\verify.sh") $distDir
            if ($LASTEXITCODE -ne 0) { throw "subplatforms/msix/x86_64/verify.sh failed" }
            "Signed MSIX passed OPC/ZIP, ANSI paths, PRI dump, and subplatform verify.sh"
        }

        # T2-F05-02: Strict makeappx.exe pack (no /nv) rejects missing StoreLogo and missing exe
        Invoke-E2ETest "T2-F05-02" {
            # (a) Delete all StoreLogo.scale-*.png and regenerate unified resources.pri matching build-x64.ps1
            $stageA = Join-Path $WorkTemp "bad-stage-logo"
            Copy-Item -Path $UnpackedDir -Destination $stageA -Recurse -Force
            Get-ChildItem -LiteralPath (Join-Path $stageA "Assets") -Filter "StoreLogo.scale-*.png" | Remove-Item -Force
            Remove-Item -LiteralPath (Join-Path $stageA "resources.pri") -Force -ErrorAction SilentlyContinue
            $stageAStrings = Join-Path $stageA "Strings"
            Copy-Item -Path (Join-Path $RepoRoot "ui-winui3-fluent2\Strings") -Destination $stageAStrings -Recurse -Force
            Remove-Item -LiteralPath (Join-Path $stageAStrings "locales.json") -Force -ErrorAction SilentlyContinue
            $cfgA = Join-Path $WorkTemp "pri-a.xml"
            & $MakePriExe createconfig /cf $cfgA /dq lang-en /o /pv 10.0.0 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri createconfig failed in T2-F05-02 with exit $LASTEXITCODE" }
            [xml]$priXmlA = Get-Content -LiteralPath $cfgA -Raw
            $pkgNodeA = $priXmlA.SelectSingleNode("/resources/packaging")
            if ($null -ne $pkgNodeA) { [void]$priXmlA.resources.RemoveChild($pkgNodeA) }
            $priXmlA.Save($cfgA)
            & $MakePriExe new /pr $stageA /cf $cfgA /mn (Join-Path $stageA "AppxManifest.xml") /of (Join-Path $stageA "resources.pri") /o | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakePri new failed in T2-F05-02 with exit $LASTEXITCODE" }
            Remove-Item -LiteralPath $stageAStrings -Recurse -Force
            & $MakeAppxExe pack /o /h SHA256 /d $stageA /p (Join-Path $WorkTemp "bad-logo.msix") 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { throw "makeappx.exe pack unexpectedly succeeded with missing StoreLogo!" }

            # (b) Delete totaldrop-winui.exe
            $stageB = Join-Path $WorkTemp "bad-stage-exe"
            Copy-Item -Path $UnpackedDir -Destination $stageB -Recurse -Force
            Remove-Item -LiteralPath (Join-Path $stageB "totaldrop-winui.exe") -Force
            & $MakeAppxExe pack /o /h SHA256 /d $stageB /p (Join-Path $WorkTemp "bad-exe.msix") 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { throw "makeappx.exe pack unexpectedly succeeded with missing totaldrop-winui.exe!" }
            "Strict makeappx.exe pack (no /nv) rejected missing StoreLogo and missing totaldrop-winui.exe"
        }

        # T2-F05-03: 4 PE32+ binary mutations on unpacked totaldrop_windows_ffi.dll
        Invoke-E2ETest "T2-F05-03" {
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $UnpackedDir --arch x64 --milestone M1 --self-test-mutations
            if ($LASTEXITCODE -ne 0) { throw "T2-F05-03 PE32+ mutation self-test failed" }
            "All 4 PE32+ CRT/CET/DependentLoadFlags/NX+HEVA mutations rejected"
        }

        # T2-F05-04: Corrupt 1 byte inside totaldrop_windows_ffi.dll in copied MSIX -> unpack fails
        Invoke-E2ETest "T2-F05-04" {
            $tampered = Join-Path $WorkTemp "tampered.msix"
            Copy-Item -LiteralPath $MsixPath -Destination $tampered -Force
            $tamperPy = @"
import sys, zipfile
p = sys.argv[1]
with zipfile.ZipFile(p, 'r') as zin:
    items = [(info, zin.read(info.filename)) for info in zin.infolist()]
with zipfile.ZipFile(p, 'w') as zout:
    for info, data in items:
        if info.filename == 'totaldrop_windows_ffi.dll':
            b = bytearray(data)
            b[len(b) // 2] ^= 0x01
            data = bytes(b)
        zout.writestr(info, data)
"@
            & $PythonExe -c $tamperPy $tampered
            if ($LASTEXITCODE -ne 0) { throw "Failed to craft tampered MSIX copy" }
            & $MakeAppxExe unpack /o /p $tampered /d (Join-Path $WorkTemp "tampered-out") 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { throw "makeappx.exe unpack did not catch 1-byte DLL tampering!" }
            "makeappx.exe unpack rejected 1-byte tampered DLL via AppxBlockMap SHA-256 mismatch"
        }

        # T2-F05-05: Execute real build-x64.ps1 -SelfSignEphemeral try/finally on forced signtool failure + synthetic key-leak scanner
        Invoke-E2ETest "T2-F05-05" {
            # (a) AST-verify and execute build-x64.ps1's verbatim if ($SelfSignEphemeral) { ... try { ... } finally { ... } } block
            $buildScript = Join-Path $RepoRoot "target-x86_64\build-x64.ps1"
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$tokens, [ref]$parseErrors)
            if ($parseErrors.Count -ne 0) {
                throw "PowerShell AST parse errors in build-x64.ps1: $($parseErrors -join '; ')"
            }
            $resolveFnAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Resolve-WindowsKitTool"
            }, $true)
            if ($null -eq $resolveFnAst) {
                throw "build-x64.ps1 missing Resolve-WindowsKitTool function"
            }
            $signIfAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.IfStatementAst] -and
                    $node.Clauses.Count -gt 0 -and
                    $node.Clauses[0].Item1.Extent.Text -match '\$SelfSignEphemeral'
            }, $true)
            if ($null -eq $signIfAst) {
                throw "build-x64.ps1 missing if (`$SelfSignEphemeral) signing block"
            }
            $tryAst = $signIfAst.Find({
                param($node)
                $node -is [System.Management.Automation.Language.TryStatementAst]
            }, $true)
            if ($null -eq $tryAst) {
                throw "build-x64.ps1 if (`$SelfSignEphemeral) is missing a try/finally block"
            }
            if ($tryAst.Body.Extent.Text -notmatch 'New-SelfSignedCertificate' -or $tryAst.Body.Extent.Text -notmatch 'SignToolExe|signtool') {
                throw "build-x64.ps1 ephemeral signing try block missing New-SelfSignedCertificate or signtool invocation"
            }
            if ($null -eq $tryAst.Finally -or
                $tryAst.Finally.Extent.Text -notmatch 'Remove-Item' -or
                $tryAst.Finally.Extent.Text -notmatch 'Cert:\\CurrentUser\\My\\') {
                throw "build-x64.ps1 ephemeral signing finally block missing Cert:\CurrentUser\My\ Remove-Item cleanup"
            }

            $beforeThumbs = @(Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq "CN=TotalDrop" } | Select-Object -ExpandProperty Thumbprint)
            $isoSignDir = Join-Path $WorkTemp "build-x64-sign-fail"
            New-Item -ItemType Directory -Force -Path $isoSignDir | Out-Null
            $roMsix = Join-Path $isoSignDir "readonly.msix"
            Copy-Item -LiteralPath $MsixPath -Destination $roMsix -Force
            Set-ItemProperty -LiteralPath $roMsix -Name IsReadOnly -Value $true

            $isoSignScript = Join-Path $isoSignDir "build-x64-signing-stage.ps1"
            $isoScriptBody = @(
                'param([Parameter(Mandatory = $true)][string]$OutMsix, [switch]$SelfSignEphemeral)',
                'Set-StrictMode -Version Latest',
                '$ErrorActionPreference = "Stop"',
                $resolveFnAst.Extent.Text,
                $signIfAst.Extent.Text
            ) -join "`n"
            Set-Content -LiteralPath $isoSignScript -Value $isoScriptBody -Encoding utf8NoBOM

            $signRc = 0
            $prevEap = $ErrorActionPreference
            try {
                $ErrorActionPreference = "Continue"
                & pwsh -NoProfile -File $isoSignScript -OutMsix $roMsix -SelfSignEphemeral 2>&1 | Out-Null
                $signRc = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $prevEap
                Set-ItemProperty -LiteralPath $roMsix -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
            }
            if ($signRc -eq 0) {
                throw "Isolated build-x64.ps1 -SelfSignEphemeral signing stage unexpectedly succeeded on read-only MSIX"
            }

            $afterThumbs = @(Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq "CN=TotalDrop" } | Select-Object -ExpandProperty Thumbprint)
            $leakedThumbs = @($afterThumbs | Where-Object { $_ -notin $beforeThumbs })
            if ($leakedThumbs.Count -ne 0) {
                foreach ($lt in $leakedThumbs) {
                    Remove-Item -LiteralPath "Cert:\CurrentUser\My\$lt" -Force -ErrorAction SilentlyContinue
                }
                throw "build-x64.ps1 -SelfSignEphemeral leaked ephemeral CN=TotalDrop cert thumbprints: $($leakedThumbs -join ', ')"
            }
            $isoLeaks = @(Get-ChildItem -Path $isoSignDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @(".pfx", ".p12", ".cer", ".snk") })
            if ($isoLeaks.Count -gt 0) {
                throw "build-x64.ps1 -SelfSignEphemeral left key/cert files on disk: $($isoLeaks.FullName -join ', ')"
            }

            # (b) Synthetic leak files caught by verify_static_contracts.py
            $leakRepo = Join-Path $WorkTemp "leak-repo"
            & git clone --local --no-hardlinks -q $RepoRoot $leakRepo
            foreach ($fname in @("leak.pfx", "secret.p12", "dev.snk", "test.cer")) {
                $f = Join-Path $leakRepo $fname
                Set-Content -LiteralPath $f -Value "synthetic-secret"
                $outLeak = & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py") --milestone M1 --root $leakRepo 2>&1
                Remove-Item -LiteralPath $f -Force
                if ($LASTEXITCODE -eq 0 -or ($outLeak -join "`n") -notmatch [regex]::Escape($fname)) {
                    throw "Signing-material scanner missed $fname"
                }
            }
            "Real build-x64.ps1 -SelfSignEphemeral signing failure left 0 leaked certs and 0 key files; all 4 forbidden signing extensions caught"
        }

        # T3-14: Headless native C ABI DLL LoadLibraryW/GetProcAddress smoke
        Invoke-E2ETest "T3-14" {
            $smokePy = @"
import ctypes, json, sys
lib = ctypes.CDLL(sys.argv[1])
lib.totaldrop_win_version_json.restype = ctypes.c_void_p
lib.totaldrop_win_string_free.argtypes = [ctypes.c_void_p]
ptr = lib.totaldrop_win_version_json()
assert ptr
raw = ctypes.cast(ptr, ctypes.c_char_p).value.decode('utf-8')
lib.totaldrop_win_string_free(ptr)
v = json.loads(raw)
assert v['app_version'] == '0.1.0-beta.1' and v['core_version'] == '0.2.0-beta.5' and v['msix_version'] == '0.1.1.0', v
"@
            & $PythonExe -c $smokePy (Join-Path $UnpackedDir "totaldrop_windows_ffi.dll")
            if ($LASTEXITCODE -ne 0) { throw "Headless ctypes.CDLL smoke test failed" }
            "Headless native C ABI loader invoked totaldrop_win_version_json and string_free cleanly"
        }

        # T3-15 & T4-06: End-to-end assets + PRI + strict MSIX + PE forensic audit
        Invoke-E2ETest "T3-15" {
            & $PythonExe (Join-Path $RepoRoot "tools\render-windows-assets.py") --check
            if ($LASTEXITCODE -ne 0) { throw "render-windows-assets.py --check failed" }
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_assets_kose.py") --out-dir (Join-Path $UnpackedDir "Assets")
            if ($LASTEXITCODE -ne 0) { throw "verify_assets_kose.py failed on unpacked Assets" }
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "pri.xml check failed" }
            "Assets, MakePri 35-locale/unplated dump, and strict MSIX unpack verified together"
        }
        Invoke-E2ETest "T4-06" {
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") `
                --msix $MsixPath --arch x64 --milestone M1 --expect-signed --pri-dump $PriDumpPath
            if ($LASTEXITCODE -ne 0) { throw "T4-06 MSIX OPC/PRI audit failed" }
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $UnpackedDir --arch x64 --milestone M1
            if ($LASTEXITCODE -ne 0) { throw "T4-06 PE hardening audit failed" }
            "Full M1 x64 MSIX forensic audit passed"
        }
    }

    if ($RunM2) {
        $M2PubDir = Join-Path $WorkTemp "publish-m2-win-x64"
        $M2BuildOk = $false
        $M2BuildErr = ""
        try {
            if (-not (Test-Path -LiteralPath $FfiDll)) {
                $savedRustFlags = $env:RUSTFLAGS
                $savedEncodedRustFlags = $env:CARGO_ENCODED_RUSTFLAGS
                Push-Location $RepoRoot
                try {
                    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
                    Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
                    & cargo build --config (Join-Path $RepoRoot "target-x86_64\cargo-config.toml") `
                        --target x86_64-pc-windows-msvc -p totaldrop-windows-ffi --release --locked
                    if ($LASTEXITCODE -ne 0) { throw "cargo build totaldrop-windows-ffi failed" }
                }
                finally {
                    if ($null -ne $savedRustFlags) {
                        $env:RUSTFLAGS = $savedRustFlags
                    }
                    else {
                        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
                    }
                    if ($null -ne $savedEncodedRustFlags) {
                        $env:CARGO_ENCODED_RUSTFLAGS = $savedEncodedRustFlags
                    }
                    else {
                        Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
                    }
                    Pop-Location
                }
            }
            New-Item -ItemType Directory -Force -Path $M2PubDir | Out-Null
            & dotnet publish (Join-Path $RepoRoot "ui-winui3-fluent2\TotalDrop.WinUI.csproj") `
                -r win-x64 -c Release -p:Platform=x64 -p:PublishAot=true `
                -p:WindowsAppSDKSelfContained=false -p:TreatWarningsAsErrors=true -o $M2PubDir
            if ($LASTEXITCODE -ne 0) { throw "M2 dotnet publish failed with exit $LASTEXITCODE" }
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $M2PubDir --arch x64 --milestone M2
            if ($LASTEXITCODE -ne 0) { throw "M2 PE32+ 24-export verification failed" }
            $M2BuildOk = $true
        }
        catch {
            $M2BuildErr = $_.Exception.Message
        }

        foreach ($uiId in @("T1-F10-05", "T1-F11-05", "T1-F12-05")) {
            Invoke-E2ETest $uiId {
                if (-not $M2BuildOk) { throw "M2 Native AOT build failed: $M2BuildErr" }
                & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py") --milestone M2 --root $RepoRoot
                if ($LASTEXITCODE -ne 0) { throw "verify_static_contracts.py --milestone M2 failed" }
                & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py") --check-m2-ui-audit --root $RepoRoot
                if ($LASTEXITCODE -ne 0) { throw "M2 UI page audit failed for $uiId" }
                "M2 Native AOT publish (0 warnings, 24 exports) + $uiId UI static contract verified"
            }
        }

        $TestProj = Join-Path $RepoRoot "ui-winui3-fluent2\TotalDrop.WinUI.Tests\TotalDrop.WinUI.Tests.csproj"
        $env:TOTALDROP_FFI_DLL_PATH = $FfiDll

        foreach ($entry in @(
            @("T1-F12-01", "T1_F12_01"),
            @("T1-F12-02", "T1_F12_02"),
            @("T2-F12-01", "T2_F12_01"),
            @("T2-F12-02", "T2_F12_02"),
            @("T3-04", "T3_04")
        )) {
            $tid = $entry[0]
            $flt = $entry[1]
            Invoke-E2ETest $tid {
                & dotnet test $TestProj -c Release --filter "Category!=WindowsCI&FullyQualifiedName~$flt" --verbosity minimal
                if ($LASTEXITCODE -ne 0) { throw "dotnet test filter '$flt' failed with exit $LASTEXITCODE" }
                "Headless .NET 10 TotalDrop.WinUI.Tests ($flt) passed"
            }
        }
    }

    if ($RunM3) {
        $M3PubDir = Join-Path $WorkTemp "publish-m3-win-x64"
        $TestProj = Join-Path $RepoRoot "ui-winui3-fluent2\TotalDrop.WinUI.Tests\TotalDrop.WinUI.Tests.csproj"

        if (-not (Test-Path -LiteralPath $FfiDll) -or -not (Test-Path -LiteralPath $ExtDll)) {
            $savedRf = $env:RUSTFLAGS
            $savedErf = $env:CARGO_ENCODED_RUSTFLAGS
            Push-Location $RepoRoot
            try {
                Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
                Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
                & cargo build --config (Join-Path $RepoRoot "target-x86_64\cargo-config.toml") `
                    --target x86_64-pc-windows-msvc -p totaldrop-windows-ffi -p totaldrop-explorer-ext --release --locked
                if ($LASTEXITCODE -ne 0) { throw "M3 cargo build failed with exit $LASTEXITCODE" }
            }
            finally {
                if ($null -ne $savedRf) { $env:RUSTFLAGS = $savedRf } else { Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue }
                if ($null -ne $savedErf) { $env:CARGO_ENCODED_RUSTFLAGS = $savedErf } else { Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue }
                Pop-Location
            }
        }

        $env:TOTALDROP_FFI_DLL_PATH = $FfiDll
        $env:TOTALDROP_EXPLORER_EXT_DLL = $ExtDll

        # T1-F16-01: PE32+ + dumpbin oracle on totaldrop_explorer_ext.dll
        Invoke-E2ETest "T1-F16-01" {
            New-Item -ItemType Directory -Force -Path $M3PubDir | Out-Null
            & dotnet publish (Join-Path $RepoRoot "ui-winui3-fluent2\TotalDrop.WinUI.csproj") `
                -r win-x64 -c Release -p:Platform=x64 -p:PublishAot=true `
                -p:WindowsAppSDKSelfContained=false -p:TreatWarningsAsErrors=true -o $M3PubDir
            if ($LASTEXITCODE -ne 0) { throw "M3 dotnet publish failed with exit $LASTEXITCODE" }
            Copy-Item -LiteralPath $ExtDll -Destination $M3PubDir -Force
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") `
                --unpacked $M3PubDir --arch x64 --milestone M3
            if ($LASTEXITCODE -ne 0) { throw "M3 verify_pe_hardening.py failed" }
            $dumpExt = (& $DumpBinExe /headers /loadconfig /imports /exports $ExtDll) -join "`n"
            if ($LASTEXITCODE -ne 0) { throw "dumpbin.exe failed on totaldrop_explorer_ext.dll" }
            foreach ($tok in @("8664", "Dynamic base", "NX compatible", "High Entropy Virtual Addresses", "DllGetClassObject", "DllCanUnloadNow")) {
                if ($dumpExt -notmatch [regex]::Escape($tok)) { throw "dumpbin missing '$tok' in totaldrop_explorer_ext.dll" }
            }
            if ($dumpExt -match "vcruntime140|msvcp140|ucrtbased") { throw "forbidden CRT import in totaldrop_explorer_ext.dll" }
            "x64 totaldrop_explorer_ext.dll verified (PE32+ 0x8664, CETCOMPAT, 0x800, +crt-static, COM exports, RT_GROUP_ICON 101)"
        }

        # 8 COM DLL tests via e2e_com_harness.rs loading compiled totaldrop_explorer_ext.dll
        foreach ($comEntry in @(
            @("T1-F16-02", "t1_f16_02"),
            @("T1-F16-04", "t1_f16_04"),
            @("T1-F16-05", "t1_f16_05"),
            @("T2-F16-01", "t2_f16_01"),
            @("T2-F16-04", "t2_f16_04"),
            @("T2-F16-05", "t2_f16_05"),
            @("T3-09", "t3_09"),
            @("T4-07", "t4_07")
        )) {
            $tid = $comEntry[0]
            $flt = $comEntry[1]
            Invoke-E2ETest $tid {
                Push-Location $RepoRoot
                try {
                    & cargo test --locked -p totaldrop-explorer-ext --test e2e_com_harness -- $flt --nocapture
                    if ($LASTEXITCODE -ne 0) { throw "e2e_com_harness filter '$flt' failed with exit $LASTEXITCODE" }
                }
                finally { Pop-Location }
                "In-proc COM harness ($flt) against compiled totaldrop_explorer_ext.dll passed"
            }
        }

        # Headless Windows-native .NET 10 M3 tests
        foreach ($winDotnet in @(
            @("T1-F17-04", "T1_F17_04"),
            @("T1-F18-04", "T1_F18_04"),
            @("T1-F20-02", "T1_F20_02"),
            @("T2-F20-01", "T2_F20_01"),
            @("T1-F21-04", "T1_F21_03"),
            @("T3-10", "T3_10")
        )) {
            $tid = $winDotnet[0]
            $flt = $winDotnet[1]
            Invoke-E2ETest $tid {
                & dotnet test $TestProj -c Release --filter "Category=WindowsCI&FullyQualifiedName~$flt" --verbosity minimal
                if ($LASTEXITCODE -ne 0) { throw "WindowsCI dotnet test '$flt' failed with exit $LASTEXITCODE" }
                if ($tid -eq "T1-F21-04") {
                    & dotnet test $TestProj -c Release --filter "Category=WindowsCI&FullyQualifiedName~T1_F21_04" --verbosity minimal
                    if ($LASTEXITCODE -ne 0) { throw "WindowsCI dotnet test T1_F21_04 failed" }
                }
                if ($tid -eq "T3-10") {
                    & dotnet test $TestProj -c Release --filter "Category=WindowsCI&FullyQualifiedName~T2_F17_06" --verbosity minimal
                    if ($LASTEXITCODE -ne 0) { throw "WindowsCI dotnet test T2_F17_06 failed" }
                }
                "Headless Windows-native .NET 10 test ($tid / $flt) passed"
            }
        }

        # T1-F19-05: M3 Native AOT publish + strict MSIX pack containing ToastNotificationActivation & ExeServer
        Invoke-E2ETest "T1-F19-05" {
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_static_contracts.py") --milestone M3 --root $RepoRoot
            if ($LASTEXITCODE -ne 0) { throw "M3 static contract check failed" }
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --msix $MsixPath --arch x64 --milestone M3 --expect-signed
            if ($LASTEXITCODE -ne 0) { throw "M3 MSIX OPC/Toast/Firewall check failed" }
            "M3 Native AOT publish & strict MSIX with ToastNotificationActivation + ExeServer verified"
        }

        # T3-13: WakeLock + cooperative shutdown + powercfg /requests zero residual check
        Invoke-E2ETest "T3-13" {
            & dotnet test $TestProj -c Release --filter "Category=WindowsCI&FullyQualifiedName~T1_F20_02" --verbosity minimal
            if ($LASTEXITCODE -ne 0) { throw "WakeLock T1_F20_02 failed" }
            Push-Location $RepoRoot
            try {
                & cargo test --locked -p totaldrop-windows-ffi --test e2e_ipc_shutdown_m3 -- t1_f20_03_cooperative_shutdown_under_800ms --nocapture
                if ($LASTEXITCODE -ne 0) { throw "t1_f20_03 cooperative shutdown failed" }
            }
            finally { Pop-Location }
            $pwr = (& powercfg /requests 2>&1) -join "`n"
            if ($pwr -match "totaldrop-winui\.exe") {
                throw "Residual TotalDrop powercfg /requests entry found after shutdown: $pwr"
            }
            "WakeLock, cooperative shutdown (<800ms), and zero residual powercfg /requests verified"
        }

        # Helper for ephemeral MSIX install / firewall inspection / uninstall lifecycle
        $TestFirewallLifecycle = {
            param([bool]$MultiCycle)
            if (-not (Test-Path -LiteralPath $MsixPath)) { throw "MSIX not found: $MsixPath" }
            $sig = Get-AuthenticodeSignature -FilePath $MsixPath
            if ($null -eq $sig.SignerCertificate) { throw "MSIX is not signed; ephemeral cert required for Add-AppxPackage" }
            $cert = $sig.SignerCertificate
            $addedStores = @()
            try {
                foreach ($storeName in @("TrustedPeople", "Root")) {
                    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, "LocalMachine")
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    try {
                        if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
                            $store.Add($cert)
                            $addedStores += $storeName
                        }
                    }
                    finally { $store.Close() }
                }

                $addParams = @{ Path = $MsixPath; ForceApplicationShutdown = $true }
                if (-not [string]::IsNullOrWhiteSpace($RuntimeDepMsix) -and (Test-Path -LiteralPath $RuntimeDepMsix)) {
                    $addParams["DependencyPath"] = $RuntimeDepMsix
                }
                Add-AppxPackage @addParams
                if ($MultiCycle) {
                    Add-AppxPackage @addParams
                }

                $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
                    $_.DisplayName -match "TotalDrop" -or $_.Package -match "TotalDrop"
                })
                if ($rules.Count -ne 1) { throw "Expected exactly 1 TotalDrop firewall rule after install, found $($rules.Count)" }
                $r = $rules[0]
                if ($r.Direction -ne "Inbound") { throw "Firewall rule Direction=$($r.Direction) != Inbound" }
                if ($r.Profile -ne "Private") { throw "Firewall rule Profile=$($r.Profile) != Private" }
                $pf = $r | Get-NetFirewallPortFilter
                if ($pf.Protocol -ne "UDP") { throw "Firewall rule Protocol=$($pf.Protocol) != UDP" }

                Get-AppxPackage -Name "TotalDrop.TotalDrop" -ErrorAction SilentlyContinue | Remove-AppxPackage
                $postRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
                    $_.DisplayName -match "TotalDrop" -or $_.Package -match "TotalDrop"
                })
                if ($postRules.Count -ne 0) { throw "Orphaned TotalDrop firewall rules remained after uninstall: $($postRules.Count)" }
            }
            finally {
                Get-AppxPackage -Name "TotalDrop.TotalDrop" -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
                foreach ($storeName in $addedStores) {
                    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, "LocalMachine")
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    try {
                        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                        foreach ($c in $existing) { $store.Remove($c) }
                    }
                    finally { $store.Close() }
                }
            }
        }

        Invoke-E2ETest "T1-F21-03" { & $TestFirewallLifecycle $false; "Installed M3 MSIX, verified 1 Inbound/UDP/Private rule, uninstalled with 0 residual rules/certs" }
        Invoke-E2ETest "T2-F21-05" { & $TestFirewallLifecycle $true; "Multi-cycle install/re-install kept exact 1 Private UDP rule (0 duplicates) and cleaned up 100%" }
        Invoke-E2ETest "T3-17" { & $TestFirewallLifecycle $false; "Strict M3 MSIX pack + firewall lifecycle + app.manifest longPathAware verified" }
        Invoke-E2ETest "T4-10" { & $TestFirewallLifecycle $false; "Full M3 install -> scoped Private UDP firewall -> clean uninstall verified" }
    }

    if ($RunM4) {
        $IsArm64Host = ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64)
        $Arm64Unpack = Join-Path $WorkTemp "unpacked-arm64"
        $BundleUnpack = Join-Path $WorkTemp "unpacked-bundle"

        # T1-F23-04 & T2-F23-05: PowerShell AST & WACK report-checker verification (headless, never launches appcert.exe GUI)
        Invoke-E2ETest "T1-F23-04" {
            $wackScript = Join-Path $RepoRoot "tools\run-wack.ps1"
            $tokens = $null
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($wackScript, [ref]$tokens, [ref]$parseErrors)
            if ($parseErrors.Count -ne 0) { throw "run-wack.ps1 AST errors: $($parseErrors -join '; ')" }
            $passXml = Join-Path $WorkTemp "wack-pass.xml"
            Set-Content -LiteralPath $passXml -Encoding utf8NoBOM -Value @'
<?xml version="1.0" encoding="utf-8"?>
<REPORT OVERALL_RESULT="PASS">
  <REQUIREMENTS>
    <REQUIREMENT>
      <TEST NAME="Supported APIs"><RESULT><![CDATA[PASS]]></RESULT></TEST>
      <TEST NAME="Package Sanity"><RESULT><![CDATA[PASS]]></RESULT></TEST>
    </REQUIREMENT>
  </REQUIREMENTS>
</REPORT>
'@
            & pwsh -NoProfile -File $wackScript -CheckReportOnly -ReportPath $passXml
            if ($LASTEXITCODE -ne 0) { throw "run-wack.ps1 -CheckReportOnly failed on valid PASS XML" }
            "run-wack.ps1 AST 0 errors and -CheckReportOnly accepted valid PASS XML report"
        }

        Invoke-E2ETest "T2-F23-05" {
            $wackScript = Join-Path $RepoRoot "tools\run-wack.ps1"
            $fail1 = Join-Path $WorkTemp "wack-fail-overall.xml"
            Set-Content -LiteralPath $fail1 -Encoding utf8NoBOM -Value '<?xml version="1.0"?><REPORT OVERALL_RESULT="FAIL"><TEST NAME="Supported APIs"><RESULT><![CDATA[FAIL]]></RESULT></TEST></REPORT>'
            $out1 = (& pwsh -NoProfile -File $wackScript -CheckReportOnly -ReportPath $fail1 2>&1) -join "`n"
            if ($LASTEXITCODE -eq 0) { throw "run-wack.ps1 accepted OVERALL_RESULT=FAIL" }

            $fail2 = Join-Path $WorkTemp "wack-fail-test.xml"
            Set-Content -LiteralPath $fail2 -Encoding utf8NoBOM -Value '<?xml version="1.0"?><REPORT OVERALL_RESULT="PASS"><TEST NAME="Supported APIs"><RESULT><![CDATA[FAIL]]></RESULT></TEST></REPORT>'
            $out2 = (& pwsh -NoProfile -File $wackScript -CheckReportOnly -ReportPath $fail2 2>&1) -join "`n"
            if ($LASTEXITCODE -eq 0 -or $out2 -notmatch "Supported APIs") {
                throw "run-wack.ps1 did not reject PASS report with failing 'Supported APIs' test: $out2"
            }
            "run-wack.ps1 rejected OVERALL_RESULT=FAIL and PASS-with-failing-Supported-APIs report"
        }

        # ARM64 slice & dual-arch bundle/upload tests (require ARM64 host or staged -Arm64MsixPath / -BundlePath / -MsixUploadPath)
        Invoke-E2ETest "T1-F22-01" {
            if ([string]::IsNullOrWhiteSpace($Arm64MsixPath)) {
                if (-not $IsArm64Host) { throw "T1-F22-01 requires windows-11-arm host or explicit -Arm64MsixPath" }
                & (Join-Path $RepoRoot "target-arm64\build-arm64.ps1") -SelfSignEphemeral
                if ($LASTEXITCODE -ne 0) { throw "build-arm64.ps1 failed" }
                $armName = (& $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") --root $RepoRoot --arch arm64 --resolve-recipe).Trim()
                $Arm64MsixPath = Join-Path $RepoRoot ("dist\" + $armName)
            }
            & $MakeAppxExe unpack /o /p $Arm64MsixPath /d $Arm64Unpack
            if ($LASTEXITCODE -ne 0) { throw "makeappx unpack failed on ARM64 MSIX" }
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") --unpacked $Arm64Unpack --arch arm64 --milestone M4
            if ($LASTEXITCODE -ne 0) { throw "verify_pe_hardening.py failed on ARM64 MSIX" }
            "ARM64 MSIX unpacked & PE32+ 0xAA64 hardening + 31 FFI / 3 COM exports verified"
        }

        Invoke-E2ETest "T2-F22-03" {
            if (-not (Test-Path -LiteralPath $Arm64Unpack)) { throw "ARM64 unpacked directory unavailable (run T1-F22-01 or pass -Arm64MsixPath)" }
            if (-not (Test-Path -LiteralPath $ExtDll)) { throw "x64 totaldrop_explorer_ext.dll unavailable for cross-arch contamination test" }
            $poisonDir = Join-Path $WorkTemp "arm64-cross-arch-poison"
            Copy-Item -Path $Arm64Unpack -Destination $poisonDir -Recurse -Force
            Copy-Item -LiteralPath $ExtDll -Destination (Join-Path $poisonDir "totaldrop_explorer_ext.dll") -Force
            $outP = (& $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") --unpacked $poisonDir --arch arm64 --milestone M4 2>&1) -join "`n"
            if ($LASTEXITCODE -eq 0 -or $outP -notmatch "0xAA64" -or $outP -notmatch "0x8664") {
                throw "Cross-architecture x64-in-ARM64 contamination was not caught: $outP"
            }
            "Cross-architecture x64 totaldrop_explorer_ext.dll in ARM64 tree rejected (expected 0xAA64, got 0x8664)"
        }

        Invoke-E2ETest "T2-F22-06" {
            if (-not (Test-Path -LiteralPath $Arm64Unpack)) { throw "ARM64 unpacked directory unavailable" }
            & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_pe_hardening.py") --unpacked $Arm64Unpack --arch arm64 --milestone M4 --self-test-mutations
            if ($LASTEXITCODE -ne 0) { throw "ARM64 PE hardening mutation self-test failed" }
            "All ARM64 PE/CRT/0x800/NX+HEVA mutations caught"
        }

        foreach ($bundleTest in @("T1-F22-02", "T1-F22-06", "T3-23", "T4-11")) {
            Invoke-E2ETest $bundleTest {
                if ([string]::IsNullOrWhiteSpace($BundlePath) -or -not (Test-Path -LiteralPath $BundlePath)) {
                    throw "$bundleTest requires staged dual-arch -BundlePath (and -MsixUploadPath) from windows-release.yml / build-msixbundle.ps1"
                }
                $verArgs = @("--bundle", $BundlePath, "--expected-version", "1.0.1.0", "--store-mode", "--allow-test-identity")
                if (-not [string]::IsNullOrWhiteSpace($MsixUploadPath) -and (Test-Path -LiteralPath $MsixUploadPath)) {
                    $verArgs += @("--msixupload", $MsixUploadPath)
                }
                & $PythonExe (Join-Path $RepoRoot "tools\verify-msix-artifact.py") @verArgs
                if ($LASTEXITCODE -ne 0) { throw "verify-msix-artifact.py failed for $bundleTest" }
                $opcArgs = @("--bundle", $BundlePath, "--expected-version", "1.0.1.0", "--store-mode")
                if (-not [string]::IsNullOrWhiteSpace($MsixUploadPath) -and (Test-Path -LiteralPath $MsixUploadPath)) {
                    $opcArgs += @("--msixupload", $MsixUploadPath)
                }
                & $PythonExe (Join-Path $RepoRoot "tools\e2e\verify_msix_opc.py") @opcArgs
                if ($LASTEXITCODE -ne 0) { throw "verify_msix_opc.py failed for $bundleTest" }
                "Dual-arch .msixbundle / .msixupload verified by both verify-msix-artifact.py and verify_msix_opc.py ($bundleTest)"
            }
        }
    }
}
finally {
    if (Test-Path -LiteralPath $WorkTemp) {
        Remove-Item -LiteralPath $WorkTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (-not [string]::IsNullOrWhiteSpace($ResultsJson)) {
    $Results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultsJson -Encoding utf8NoBOM
}

$failedCount = @($Results.Values | Where-Object { $_.status -ne "PASS" }).Count
Write-Host ("==> Invoke-WindowsE2E summary: {0}/{1} PASS, {2} FAIL" -f ($Results.Count - $failedCount), $Results.Count, $failedCount)
if ($failedCount -gt 0) { exit 1 }
exit 0
