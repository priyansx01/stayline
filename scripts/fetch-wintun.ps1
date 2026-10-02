# Downloads the signed Wintun driver DLL from wintun.net, checks its hash and
# copies wintun.dll next to the stayline executables in target\.
#
#   powershell -ExecutionPolicy Bypass -File scripts\fetch-wintun.ps1

$ErrorActionPreference = 'Stop'

$version = '0.14.1'
$sha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
$arch = 'amd64'

$root = Split-Path -Parent $PSScriptRoot
$cache = Join-Path $root 'target\wintun'
$zip = Join-Path $cache "wintun-$version.zip"

New-Item -ItemType Directory -Force $cache | Out-Null
if (-not (Test-Path $zip)) {
    Write-Host "downloading wintun $version"
    Invoke-WebRequest -UseBasicParsing "https://www.wintun.net/builds/wintun-$version.zip" -OutFile $zip
}

$actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
if ($actual -ne $sha256) {
    Remove-Item $zip
    throw "wintun-$version.zip hash mismatch: expected $sha256, got $actual"
}

Expand-Archive -Force $zip $cache
$dll = Join-Path $cache "wintun\bin\$arch\wintun.dll"

foreach ($profile in 'debug', 'release') {
    $dir = Join-Path $root "target\$profile"
    New-Item -ItemType Directory -Force $dir | Out-Null
    Copy-Item -Force $dll $dir
    Write-Host "wintun.dll -> $dir"
}
