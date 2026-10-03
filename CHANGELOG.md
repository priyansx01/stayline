# Changelog

All notable changes to Stayline VPN are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Licence files, contributing guide, security policy, code of conduct and documentation in `docs/`.
- GitHub Actions: CI (format, clippy, tests) and a release workflow that publishes the MSI.

### Changed
- Installer sources moved to `packaging/`.

## [0.1.1] - 2026-10-03

### Added
- Sign-in prompt when connecting a profile without a saved password; a rejected password brings it back.
- First connection to a gateway with a non-public certificate asks for approval in a dialog showing the fingerprint.
- The app starts the service when it is installed but stopped, and tells apart a missing, starting and stopped service.
- Stayline VPN artwork in the installer.

### Changed
- Product name is now **Stayline VPN**.
- New interface: white sidebar with Status, Profiles, Settings and About, compact panels and a new vector logo.
- Gateway address and port are separate fields.
- Fingerprints are shown in blocks of eight.
- An installer with the same version now replaces the installed one instead of installing beside it.

### Fixed
- Long placeholders and fingerprints no longer overflow their fields; the Slint badge on About fits its panel.

## [0.1.0] - 2026-10-02

### Added
- FortiGate SSL-VPN login, tunnel over PPP and certificate pinning.
- Automatic reconnect after network changes, Wi-Fi drops and sleep, with back-off and offline detection.
- Windows service that owns the tunnel, and a tray app with status, profiles and settings.
- Saved passwords encrypted with Windows DPAPI.
- Company-managed connections, multiple profiles and trust-on-first-use certificates.
- MSI installer, including company installers with a built-in connection.
- About page listing every open-source component and its licence.

[Unreleased]: https://github.com/priyansx01/stayline-vpn/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/priyansx01/stayline-vpn/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/priyansx01/stayline-vpn/releases/tag/v0.1.0
