# Architecture

Stayline VPN is split into a Windows service that owns the tunnel and a tray app that only shows state and collects input. The tunnel never depends on the app: closing or crashing the tray leaves the VPN up.

```
┌──────────────────────┐   named pipe    ┌──────────────────────────────┐
│ stayline-tray.exe    │ \\.\pipe\stayline │ stayline-svc.exe (LocalSystem) │
│ per user             │◄───────────────►│                              │
│ window, tray icon,   │  JSON lines     │ supervisor ─ tunnel ─ PPP    │
│ notifications,       │                 │      │                       │
│ saved passwords      │                 │ Wintun adapter, routes, DNS  │
└──────────────────────┘                 └──────────────┬───────────────┘
                                                        │ TLS
                                                        ▼
                                              FortiGate SSL-VPN gateway
```

## Crates

| Crate | Kind | Responsibility |
| --- | --- | --- |
| [`stayline-core`](../crates/core) | lib | FortiGate login, XML config, TLS with certificate pinning, the tunnel, a small sans-IO PPP (LCP, IPCP, echo) and the reconnect supervisor. No Windows code. |
| [`stayline-config`](../crates/config) | lib | Company-managed connections, user settings, saved passwords (DPAPI). |
| [`stayline-ipc`](../crates/ipc) | lib | Messages between the tray and the service, and the pipe's access control. |
| [`stayline-net`](../crates/net) | lib | Windows only: Wintun adapter, address, MTU, routes and DNS through the IP Helper API, and network-change notifications. |
| [`stayline-svc`](../crates/svc) | bin | The Windows service; also `install`, `uninstall`, `run`, `provision` and `unprovision` commands. |
| [`stayline-tray`](../crates/tray) | bin | Slint window, tray icon, notifications, sign-in and trust prompts. |
| [`stayline-probe`](../crates/probe) | bin | Developer CLI to test login and the tunnel against a gateway. |

## Connecting

1. `POST /remote/logincheck` with username, password and optional realm. (`stayline-core` recognises a token challenge and `stayline-probe` can answer it; the app supports username and password only, and SAML is not supported.)
2. `GET /remote/fortisslvpn_xml` returns the tunnel address, routes (split or full tunnel), DNS servers and session timeouts.
3. `GET /remote/sslvpn-tunnel` upgrades the TLS connection to the tunnel; PPP frames are carried with Fortinet's 6-byte header.
4. PPP negotiates LCP and IPCP, then IPv4 packets flow between the tunnel and the Wintun adapter.

Certificates are checked against Windows' public roots, or against a pinned SHA-256 fingerprint. An unpinned, non-public certificate stops the connection and asks the user (or IT, through the pin) to confirm it.

## Staying connected

- **Detecting a drop:** LCP echo every 10 s, plus Windows route, interface and address change notifications and sleep/resume.
- **During a drop:** the adapter and routes stay in place, so applications see a pause rather than a lost network.
- **Reconnecting:** waits for a usable network, then retries with a back-off of 1 s, 2 s, 4 s … up to 60 s, and at once whenever the network changes. It reuses the session cookie while the gateway accepts it, then logs in again with the password.
- **Stopping:** only for problems the user must fix (rejected password, changed or untrusted certificate). The service reports these to the tray, which notifies the user and opens a prompt.

## Files

| Path | Written by | Contents |
| --- | --- | --- |
| `%ProgramData%\stayline\connections.toml` | installer / `stayline-svc provision` (admin) | Company connections, read-only for users. |
| `%APPDATA%\stayline\config\settings.toml` | tray | The user's own profiles, trusted certificates and preferences. |
| `%LOCALAPPDATA%\stayline\data\credentials\` | tray | Saved passwords, encrypted with DPAPI for the current Windows user. |
| `%ProgramData%\stayline\logs\` | service | Service logs. |
| `%LOCALAPPDATA%\stayline\data\logs\` | tray | App logs. |

## Security notes

- The pipe allows SYSTEM and administrators full access and interactive users read/write; other accounts cannot connect.
- Passwords are sent to the service only for the connection being made and are never written by the service.
- The service grants interactive users the right to **start** it (not stop or reconfigure), so the app can bring it back if it was stopped.
