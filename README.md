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

`wintun.dll` (from wintun.net) must sit next to `stayline-svc.exe` / `stayline-probe.exe` at runtime.

## Checking a gateway

```
# Show the gateway certificate fingerprint (to pin a self-signed certificate)
cargo run -p stayline-probe -- cert vpn.example.com:10443

# Log in and print the assigned IP, routes, DNS and session timeouts
cargo run -p stayline-probe -- login vpn.example.com:10443 --user alice [--pin <sha256>]
```

The password is prompted for (or read from `STAYLINE_PASSWORD`). If the gateway asks for a token code, the probe asks for it too. The output shows whether the gateway offers PPP tunnel mode and how long a session can be reused, which decides how far silent reconnects can go.

## Status

- [x] Workspace scaffold
- [x] Login probe
- [ ] Tunnel up
- [ ] Reconnect engine
- [ ] Service + tray split
- [ ] Login and settings window
- [ ] MSI package
