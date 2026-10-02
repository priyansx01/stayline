# Regenerates the third-party notices after dependencies change:
#   THIRD-PARTY-NOTICES.html   full licence texts, shipped with the installer
#   crates\tray\third-party.txt  component list shown on the About page
#
#   powershell -ExecutionPolicy Bypass -File scripts\gen-notices.ps1
# Needs: cargo install cargo-about --locked --features cli

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$wintunLicense = Join-Path $root 'target\wintun\wintun\LICENSE.txt'
if (-not (Test-Path $wintunLicense)) {
    & (Join-Path $PSScriptRoot 'fetch-wintun.ps1')
}
$registry = Join-Path $env:USERPROFILE '.cargo\registry\src'
$slintLicense = Get-ChildItem $registry -Recurse -Filter 'LicenseRef-Slint-Royalty-free-2.0.md' |
    Where-Object { $_.FullName -match 'i-slint-core-' } | Select-Object -First 1
if (-not $slintLicense) { throw 'Slint licence text not found; run cargo fetch first' }

function Escape([string]$text) {
    [System.Net.WebUtility]::HtmlEncode($text)
}

$html = Join-Path $root 'THIRD-PARTY-NOTICES.html'
cargo about generate --workspace notices\notices.hbs -o $html
if ($LASTEXITCODE -ne 0) { throw 'cargo about failed' }
$content = [IO.File]::ReadAllText($html)
$content = $content.Replace('<!-- SLINT_LICENSE -->', (Escape ([IO.File]::ReadAllText($slintLicense.FullName))))
$content = $content.Replace('<!-- WINTUN_LICENSE -->', (Escape ([IO.File]::ReadAllText($wintunLicense))))
[IO.File]::WriteAllText($html, $content, (New-Object Text.UTF8Encoding $false))

$list = Join-Path $root 'crates\tray\third-party.txt'
cargo about generate --workspace notices\list.hbs -o $list
if ($LASTEXITCODE -ne 0) { throw 'cargo about failed' }
# Show the licence stayline actually uses for Slint, not the whole choice.
$lines = @("wintun.dll`t0.14.1`tWintun Prebuilt Binaries License") +
    (Get-Content $list | Where-Object { $_ } | ForEach-Object {
        $_ -replace '\t[^\t]*LicenseRef-Slint-Royalty-free-2\.0[^\t]*$', "`tSlint Royalty-free License 2.0"
    })
[IO.File]::WriteAllText($list, (($lines | Sort-Object) -join "`n") + "`n", (New-Object Text.UTF8Encoding $false))

Write-Host "wrote $html and $list ($($lines.Count) components)"
