# Deploying to a company

Stayline VPN is designed so IT sets up the connection once and employees only ever type their username and password.

## Choose an installer

**Company installer** — the connection is built into the MSI. Employees run it and sign in.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1 `
    -Name "Example VPN" -Gateway vpn.example.com:10443 -Pin <sha256>
```

**Generic installer** — the same MSI for everyone; pass the connection when installing (Intune, Group Policy, SCCM or a script):

```powershell
msiexec /i stayline-0.1.1.msi GATEWAY=vpn.example.com:10443 PIN=<sha256> CONNECTIONNAME="Example VPN" /qn
```

| Script option | MSI property | Meaning |
| --- | --- | --- |
| `-Name` | `CONNECTIONNAME` | Name shown to users (default "Company VPN"). |
| `-Gateway` | `GATEWAY` | `host` or `host:port` (port defaults to 443). |
| `-Pin` | `PIN` | SHA-256 fingerprint of the gateway certificate. Leave out if the certificate is publicly trusted. |
| `-Realm` | `REALM` | Realm, if the gateway uses one. |
| `-UserConnections yes\|no` | `USERCONNECTIONS` | Whether users may add their own profiles (default `no`). |
| `-TrustPrompt yes\|no` | `TRUSTPROMPT` | Whether users may accept an unpinned certificate on first connect (default `yes`). |

The MSI lands in `target\installer`.

## Getting the certificate fingerprint

```powershell
stayline-probe cert vpn.example.com:10443
```

Confirm the fingerprint with whoever runs the gateway before distributing it. When the certificate is renewed, ship the new pin (rebuild the installer or re-provision) before the old certificate is retired; users see a "certificate has changed" warning and Stayline VPN will not connect until the pin matches.

## What the installer does

- Installs the service, app and `wintun.dll` to `C:\Program Files\Stayline VPN`.
- Registers the **Stayline VPN** service (automatic start, LocalSystem, restarts on failure).
- Adds a Start-menu entry and starts the app at sign-in for every user (each user can turn this off in Settings).
- Writes the company connection to `%ProgramData%\stayline\connections.toml`, which users can read but not change.

Upgrades keep the company connection; uninstalling removes it, the service and the program files. Users' own settings and saved passwords stay in their profile unless deleted.

## Managing connections on a machine

From an elevated prompt:

```powershell
stayline-svc provision --name "Example VPN" --gateway vpn.example.com:10443 --pin <sha256> `
    [--realm <realm>] [--user-connections yes|no] [--trust-prompt yes|no]
stayline-svc unprovision --name "Example VPN"
stayline-svc unprovision --all
```

## Logs for support

- Service: `%ProgramData%\stayline\logs`
- App: `%LOCALAPPDATA%\stayline\data\logs` (Settings → **Open logs folder**)
