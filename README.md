# stayline

A lightweight Windows VPN client, written in Rust, for FortiGate SSL-VPN gateways. It has one job: keep the tunnel up, and reconnect on its own after minutes or hours offline without asking for the password again.

## Goals

- Connect to an existing FortiGate SSL-VPN gateway (no server changes).
- Survive Wi-Fi drops, network switches and sleep/resume.
- Only prompt when the gateway asks for something new (token code, SAML, changed password).
- Optional "Save password": stored on disk encrypted with Windows DPAPI, readable only by the same Windows user.
- System tray app, starts at boot, under ~30 MB RAM idle.
- Windows 10 2004+ and Windows 11, x86_64.

Not in scope: IPsec/IKEv2, posture checks, EMS, web filtering, macOS/Linux.

## Layout

| Crate | Kind | Responsibility |
| --- | --- | --- |
| `stayline-core` | lib | FortiGate login, XML config, tunnel, minimal PPP (LCP, IPCP, echo), reconnect state machine. No Windows code. |
| `stayline-ipc` | lib | Messages between tray and service over a named pipe. |
| `stayline-net` | lib | Windows only: Wintun adapter, address, MTU, routes and DNS through the IP Helper API. |
| `stayline-svc` | bin | Windows service (LocalSystem). Owns the Wintun adapter, routes, DNS and the reconnect loop. |
| `stayline-tray` | bin | Tray icon and menu, login/settings window, notifications, saved password. |
| `stayline-probe` | bin | Developer CLI for testing login and the tunnel against a gateway. |

## Reconnect behaviour

1. Detect a drop: LCP echo every 10 s (dead after 3 misses), network-change and sleep/resume events.
2. Keep the adapter and routes in place during a drop.
3. Wait for internet, then back off 1 s, 2 s, 4 s … up to 60 s.
4. Reuse the in-memory session cookie, then log in with the saved password, and only then ask the user.

## Building

Requires the MSVC build tools and Windows SDK. The toolchain version is pinned in `rust-toolchain.toml`.

```
cargo build --workspace
cargo test --workspace
```

`wintun.dll` (from wintun.net) must sit next to `stayline-svc.exe` / `stayline-probe.exe` at runtime. This downloads it, checks its hash and copies it into `target\debug` and `target\release`:

```
powershell -ExecutionPolicy Bypass -File scripts\fetch-wintun.ps1
```

## Checking a gateway

```
# Show the gateway certificate fingerprint (to pin a self-signed certificate)
cargo run -p stayline-probe -- cert vpn.example.com:10443

# Log in and print the assigned IP, routes, DNS and session timeouts
cargo run -p stayline-probe -- login vpn.example.com:10443 --user alice [--pin <sha256>]
```

The password is prompted for (or read from `STAYLINE_PASSWORD`). If the gateway asks for a token code, the probe asks for it too. The output shows whether the gateway offers PPP tunnel mode and how long a session can be reused, which decides how far silent reconnects can go.

To bring the tunnel up in the foreground, from an **elevated** prompt:

```
cargo run -p stayline-probe -- tunnel vpn.example.com:10443 --user alice [--pin <sha256>]
```

This creates a `stayline` network adapter, sets its address, routes and DNS, and stays connected until Ctrl+C. If the connection drops (Wi-Fi off, network switch, sleep) it keeps the adapter and routes, logs in again with the password it was given and backs off 1 s, 2 s, 4 s … up to 60 s, retrying at once when Windows reports a network change. It stops retrying only for problems the user must fix, such as a rejected password. Run with `RUST_LOG=stayline_core=debug` to see PPP negotiation.

## Running as a service with the tray app

Until the installer exists, set it up by hand. From an **elevated** prompt, copy the service next to `wintun.dll` and register it (auto start, LocalSystem, restarts on failure):

```
mkdir "C:\Program Files\stayline"
copy target\debug\stayline-svc.exe "C:\Program Files\stayline\"
copy target\debug\wintun.dll "C:\Program Files\stayline\"
"C:\Program Files\stayline\stayline-svc.exe" install
```

Then, as your normal user, start the app with `target\debug\stayline-tray.exe`. Its window has:

- **Status**: state, tunnel address, connected time and traffic, Connect/Disconnect.
- **Connection**: gateway, username, password (optionally saved, encrypted with DPAPI for your Windows account), realm, and the gateway certificate. *Check certificate* fetches the gateway's certificate through the service; *Trust this certificate* pins its SHA-256 fingerprint.
- **Preferences**: connect automatically, start at Windows sign-in, open the logs folder.

The tray icon shows grey (off), amber (connecting or reconnecting), green (connected) or red (needs you, or the service is not running). Left-click opens the window; starting the app again also brings the window up. Closing the window or quitting the tray leaves the tunnel up, and if the service restarts the tray reconnects unless you disconnected. When stayline needs you (rejected password, changed or untrusted certificate) it stops retrying, shows a notification and opens the window. Settings live in `%APPDATA%\stayline\config\settings.toml`.

The UI is built with [Slint](https://slint.dev) under its royalty-free licence, which requires the "Made with Slint" attribution shown on the About page. Logs: `%ProgramData%\stayline\logs` (service) and `%LOCALAPPDATA%\stayline\data\logs` (tray). `stayline-svc run` runs the service in a console for debugging; `stayline-svc uninstall` removes it.

Known limitation: with split tunnelling, the tunnel's DNS servers get the lowest interface metric, so Windows asks them first for all names, not only the split-DNS domains.

## Status

- [x] Workspace scaffold
- [x] Login probe
- [x] Tunnel up (tested against a FortiGate with split tunnelling)
- [x] Reconnect engine (network-change and echo based; sleep/resume events come with the service)
- [x] Service + tray split
- [x] Login and settings window
- [ ] MSI package
