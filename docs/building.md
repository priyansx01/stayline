# Building from source

## Requirements

- Windows 10 2004+ or Windows 11, x64
- [Rust](https://rustup.rs) — the exact toolchain (1.99.0, with rustfmt and clippy) is pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) and installed automatically by rustup
- Visual Studio Build Tools with the "Desktop development with C++" workload (MSVC and the Windows SDK)
- For the installer only: the [.NET SDK](https://dotnet.microsoft.com/download) 8 or later. WiX Toolset 5 is restored as a repo-local tool.

## Build and test

```powershell
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

`wintun.dll` (from [wintun.net](https://www.wintun.net)) must sit next to `stayline-svc.exe` and `stayline-probe.exe` at runtime. This downloads it, checks its hash and copies it into `target\debug` and `target\release`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\fetch-wintun.ps1
```

## Running the service and app from a build

From an **elevated** prompt, either run the service in the console:

```powershell
target\debug\stayline-svc.exe run
```

or register it as a real service (auto start, LocalSystem, restarts on failure):

```powershell
mkdir "C:\Program Files\Stayline VPN"
copy target\debug\stayline-svc.exe "C:\Program Files\Stayline VPN\"
copy target\debug\wintun.dll "C:\Program Files\Stayline VPN\"
& "C:\Program Files\Stayline VPN\stayline-svc.exe" install
```

`stayline-svc uninstall` removes it again. Then start the app as your normal user:

```powershell
target\debug\stayline-tray.exe
```

## Testing against a gateway

`stayline-probe` exercises the protocol without the service or app:

```powershell
# Show the gateway certificate fingerprint (to pin a self-signed certificate)
cargo run -p stayline-probe -- cert vpn.example.com:10443

# Log in and print the assigned address, routes, DNS and session timeouts
cargo run -p stayline-probe -- login vpn.example.com:10443 --user alice [--pin <sha256>]

# Bring the tunnel up in the foreground until Ctrl+C (elevated prompt)
cargo run -p stayline-probe -- tunnel vpn.example.com:10443 --user alice [--pin <sha256>]
```

The password is prompted for, or read from `STAYLINE_PASSWORD`. Set `RUST_LOG=stayline_core=debug` to see PPP negotiation.

## Building the installer

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
```

This builds the release binaries, fetches `wintun.dll` if needed and writes `target\installer\stayline-<version>.msi`. See [deployment.md](deployment.md) for company installers. The WiX source is [`packaging/windows/stayline.wxs`](../packaging/windows/stayline.wxs).

## Assets and notices

- `python scripts\make-logo.py` (needs Pillow) regenerates the logo, the app icon and the installer artwork in [`assets/`](../assets) from geometry.
- `scripts\gen-notices.ps1` (needs `cargo install cargo-about --locked --features cli`) regenerates `THIRD-PARTY-NOTICES.html` and the component list on the About page. Run it after changing dependencies. Templates live in [`packaging/notices/`](../packaging/notices).
