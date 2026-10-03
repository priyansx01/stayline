<#
.SYNOPSIS
Builds the stayline MSI installer.

.DESCRIPTION
Without -Gateway this builds a generic installer; IT can still pass a
company connection when installing:
  msiexec /i stayline-<version>.msi GATEWAY=vpn.example.com:10443 PIN=<sha256> /qn

With -Gateway the company connection is built in, so employees just run the
MSI and enter their username and password.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1 -Name "Company VPN" -Gateway vpn.example.com:10443 -Pin <sha256>
#>
param(
    [string]$Name = 'Company VPN',
    [string]$Gateway = '',
    [string]$Pin = '',
    [string]$Realm = '',
    # Connections are IT's job: users cannot add their own unless allowed here.
    [ValidateSet('yes', 'no')][string]$UserConnections = 'no',
    [ValidateSet('yes', 'no')][string]$TrustPrompt = 'yes',
    [string]$Output = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Run([string]$what, [scriptblock]$command) {
    Write-Host "== $what" -ForegroundColor Cyan
    & $command
    if ($LASTEXITCODE -ne 0) { throw "$what failed" }
}

$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value

Run 'release build' { cargo build --release -p stayline-svc -p stayline-tray }
if (-not (Test-Path target\release\wintun.dll)) {
    Run 'fetch wintun' { powershell -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-wintun.ps1 }
}
if (-not (Test-Path THIRD-PARTY-NOTICES.html)) {
    Run 'third-party notices' { powershell -NoProfile -ExecutionPolicy Bypass -File scripts\gen-notices.ps1 }
}

Run 'wix tool' { dotnet tool restore }
foreach ($ext in 'WixToolset.Util.wixext', 'WixToolset.UI.wixext') {
    Run "wix extension $ext" { dotnet wix extension add -g "$ext/5.0.2" }
}

if (-not $Output) {
    $suffix = if ($Gateway) { '-' + (($Name.ToLower() -replace '[^a-z0-9]+', '-').Trim('-')) } else { '' }
    $Output = "target\installer\stayline-$version$suffix.msi"
}
New-Item -ItemType Directory -Force (Split-Path $Output) | Out-Null

Run 'wix build' {
    dotnet wix build packaging\windows\stayline.wxs -arch x64 `
        -ext WixToolset.Util.wixext -ext WixToolset.UI.wixext `
        -d "Version=$version" -d "Root=$root" -d "Bin=$root\target\release" `
        -d "ConnectionName=$Name" -d "Gateway=$Gateway" -d "Pin=$Pin" -d "Realm=$Realm" `
        -d "UserConnections=$UserConnections" -d "TrustPrompt=$TrustPrompt" `
        -o $Output
}
Write-Host "built $Output" -ForegroundColor Green
