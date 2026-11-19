# Build a standalone Windows x64 viewer entirely inside this checkout.
# First setup: .\build-windows.ps1 -Bootstrap -RunTests
# Subsequent builds: .\build-windows.ps1
[CmdletBinding()]
param(
    [switch]$Bootstrap,
    [switch]$RunTests,
    [ValidateRange(1, 64)][int]$Jobs = 8
)

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$fso = New-Object -ComObject Scripting.FileSystemObject
$shortRoot = $fso.GetFolder($projectRoot).ShortPath.Replace('\', '/')
if ($shortRoot.Contains(' ')) {
    throw 'This build needs a Windows short path without spaces for the compiler and libraries.'
}
$msysRoot = "$shortRoot/.tools/msys64"
$prefix = "$msysRoot/ucrt64"
$buildDir = "$shortRoot/build/windows-release"
$distDir = Join-Path $projectRoot 'dist'
$toolDir = Join-Path $projectRoot '.tools'

function Invoke-BuildTool {
    param([string]$File, [string[]]$ToolArguments)
    # Windows PowerShell can turn a native tool's stderr warnings into errors.
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $File @ToolArguments
        $result = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($result -ne 0) { throw "$File failed with exit code $result" }
}

New-Item -ItemType Directory -Force $toolDir, $distDir,
    (Join-Path $projectRoot 'build') | Out-Null

# Keep generated tools and artifacts out of commits without changing upstream's
# ignore rules. Source files in build-support remain available for review.
$excludePath = Join-Path $projectRoot '.git/info/exclude'
if (Test-Path -LiteralPath $excludePath) {
    $excludes = Get-Content -LiteralPath $excludePath
    foreach ($entry in @('/.tools/', '/build/', '/dist/')) {
        if ($excludes -notcontains $entry) {
            Add-Content -LiteralPath $excludePath -Value $entry
        }
    }
}

if ($Bootstrap -and -not (Test-Path -LiteralPath "$msysRoot/usr/bin/bash.exe")) {
    $archiveUrl = 'https://github.com/msys2/msys2-installer/releases/download/2026-09-27/msys2-base-x86_64-20260927.sfx.exe'
    $archivePath = Join-Path $toolDir 'msys2-base.sfx.exe'
    Invoke-WebRequest -UseBasicParsing -Uri $archiveUrl -OutFile $archivePath
    $expectedHash = 'AD336CCCFDA47758B5E15CDA993FBBA421115CB0B126697DAEF1EE4DFE37209F'
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $expectedHash) {
        throw 'MSYS2 archive SHA256 verification failed.'
    }
    Invoke-BuildTool $archivePath @('-y', "-o$toolDir")
}

if (-not (Test-Path -LiteralPath "$msysRoot/usr/bin/bash.exe")) {
    throw 'Local build tools are missing. Run this script with -Bootstrap.'
}

$savedPath = $env:PATH
$savedSystem = $env:MSYSTEM
$savedInvoking = $env:CHERE_INVOKING
try {
    $env:PATH = "$prefix/bin;$msysRoot/usr/bin;$savedPath"
    $env:MSYSTEM = 'UCRT64'
    $env:CHERE_INVOKING = '1'

    if ($Bootstrap) {
        # A core MSYS2 update exits its shell; the second invocation completes it.
        Invoke-BuildTool "$msysRoot/usr/bin/bash.exe" @('--login', '-c', 'pacman -Syu --noconfirm')
        Invoke-BuildTool "$msysRoot/usr/bin/bash.exe" @('--login', '-c', 'pacman -Syu --noconfirm')
        $packages = @(
            'make', 'mingw-w64-ucrt-x86_64-gcc',
            'mingw-w64-ucrt-x86_64-cmake', 'mingw-w64-ucrt-x86_64-ninja',
            'mingw-w64-ucrt-x86_64-pkgconf', 'mingw-w64-ucrt-x86_64-fltk1.3',
            'mingw-w64-ucrt-x86_64-libjpeg-turbo', 'mingw-w64-ucrt-x86_64-gnutls',
            'mingw-w64-ucrt-x86_64-pixman', 'mingw-w64-ucrt-x86_64-nettle',
            'mingw-w64-ucrt-x86_64-gmp', 'mingw-w64-ucrt-x86_64-gtest',
            'mingw-w64-ucrt-x86_64-jsoncpp'
        )
        Invoke-BuildTool "$msysRoot/usr/bin/bash.exe" @('--login', '-c',
            ('pacman -S --noconfirm --needed --disable-download-timeout ' + ($packages -join ' ')))
    }

    $cmakeArgs = @(
        '-G', 'Ninja', '-S', $shortRoot, '-B', $buildDir,
        '-DCMAKE_BUILD_TYPE=Release', "-DCMAKE_PREFIX_PATH=$prefix",
        "-DCMAKE_PROJECT_tigervnc_INCLUDE=$shortRoot/build-support/windows-static.cmake",
        "-DCMAKE_INSTALL_PREFIX=$shortRoot/dist/install",
        '-DBUILD_VIEWER=ON', '-DENABLE_GNUTLS=ON', '-DENABLE_NETTLE=ON',
        '-DENABLE_H264=ON', '-DENABLE_AUDIO=ON', '-DENABLE_NLS=OFF'
    )
    Invoke-BuildTool "$prefix/bin/cmake.exe" $cmakeArgs
    Invoke-BuildTool "$prefix/bin/cmake.exe" @('--build', $buildDir,
        '--target', 'vncviewer', '--parallel', "$Jobs")

    if ($RunTests) {
        $targets = @('configargs', 'conv', 'convertlf', 'gesturehandler',
            'hostport', 'parameters', 'pixelformat', 'shortcuthandler',
            'unicode', 'emulatemb', 'h264decoder', 'scalegeometry', 'portableconfig',
            'scaled_surface', 'clientcompatibility', 'connectionstore')
        Invoke-BuildTool "$prefix/bin/cmake.exe" (@('--build', $buildDir,
            '--parallel', "$Jobs", '--target') + $targets)
        Invoke-BuildTool "$prefix/bin/ctest.exe" @('--test-dir', "$buildDir/tests/unit",
            '--output-on-failure', '--parallel', "$Jobs", '--output-junit',
            "$shortRoot/build/unit-results.xml")
    }

    $outputExe = Join-Path $distDir 'vncviewer.exe'
    Copy-Item -LiteralPath "$buildDir/vncviewer/vncviewer.exe" -Destination $outputExe
    Invoke-BuildTool "$prefix/bin/strip.exe" @('--strip-unneeded', $outputExe)

    $imports = & "$prefix/bin/objdump.exe" -p $outputExe
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect executable dependencies.' }
    $dllNames = @($imports | Select-String 'DLL Name:\s*(\S+)' |
        ForEach-Object { $_.Matches[0].Groups[1].Value })
    if ($dllNames.Count -eq 0) { throw 'Executable import list was empty.' }
    foreach ($dll in $dllNames) {
        if ($dll -notmatch '^api-ms-win-' -and
            -not (Test-Path -LiteralPath (Join-Path "$env:SystemRoot/System32" $dll))) {
            throw "Standalone build still needs a non-system DLL: $dll"
        }
    }

    $revision = & git -C $projectRoot rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Could not determine source revision.' }
    $sourceStatus = @(& git -C $projectRoot status --porcelain)
    if ($LASTEXITCODE -ne 0) { throw 'Could not determine source status.' }
    $packagesInstalled = & "$msysRoot/usr/bin/pacman.exe" -Q
    if ($LASTEXITCODE -ne 0) { throw 'Could not record build dependencies.' }
    [ordered]@{
        sourceCommit = "$revision"
        sourceHasLocalChanges = $sourceStatus.Count -gt 0
        configuration = 'Release, Windows x64, standalone, English UI'
        features = @('Apple DH authentication', 'TLS', 'RSA-AES', 'H.264', 'audio',
            'Scale desktop to window', 'Portable JSON settings',
            'macOS RGB565 compatibility', 'Connection manager with nested folders',
            'AES-256-GCM passwords with Windows account protected key',
            'Four-second connection deadline and return to connection manager',
            'Context menu, persistent sibling order and folder state', 'Rate-limited ICMP presence indicators')
        bytes = (Get-Item -LiteralPath $outputExe).Length
        sha256 = (Get-FileHash -LiteralPath $outputExe -Algorithm SHA256).Hash
        systemDlls = $dllNames
        packages = @($packagesInstalled)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $distDir 'build-info.json') -Encoding UTF8
    Write-Output "Standalone viewer: $outputExe"
} finally {
    $env:PATH = $savedPath
    $env:MSYSTEM = $savedSystem
    $env:CHERE_INVOKING = $savedInvoking
}
