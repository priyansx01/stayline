# User guide

## Install

Download `stayline-<version>.msi` from [Releases](https://github.com/priyansx01/stayline-vpn/releases) (or use the installer your IT department gave you) and run it. Stayline VPN starts at the end of setup and at every sign-in. If you have FortiClient connected, disconnect it first.

## Connect

- **Company installer:** your connection is already there. Open **Status**, press **Connect** and enter your password.
- **Generic installer:** go to **Profiles → Add**, enter a name, the gateway address and port, and your username, then **Save and connect**.

If no password is saved, Stayline VPN asks for it when you connect. Turn on **Save password for this Windows account** to store it encrypted (Windows DPAPI); only your Windows account on this PC can read it, and Stayline VPN then reconnects without asking.

### First connection to a gateway

If the gateway's certificate is not issued by a public authority, a **Trust this gateway?** dialog shows its SHA-256 fingerprint. Compare it with the one from your IT department, then choose **Trust and connect** or **Deny**. Stayline VPN remembers the certificate and warns you if it ever changes — if that happens, don't connect; contact IT.

## While connected

The **Status** page shows how long you have been connected, your tunnel address and the traffic sent and received. The tray icon shows the state at a glance:

| Icon | Meaning |
| --- | --- |
| Grey | Disconnected |
| Amber | Connecting or reconnecting |
| Green | Connected |
| Red | Needs you (wrong password, certificate problem) or the service is not running |

When Wi-Fi drops, you switch networks or the PC sleeps, Stayline VPN reconnects by itself. It only stops and asks you when something needs your attention, such as a changed password.

Closing the window keeps the VPN running; use the tray icon to reopen it.

## Settings

- **Connect automatically** when Stayline VPN starts (needs a saved password).
- **Start with Windows**.
- **Appearance:** light, dark or follow Windows.
- **Open logs folder** — useful when IT asks for details.

## Uninstall

Use **Settings → Apps → Installed apps → Stayline VPN → Uninstall**. To also remove your profiles and saved passwords, delete `%APPDATA%\stayline` and `%LOCALAPPDATA%\stayline`.
