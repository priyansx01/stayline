# Contributing to Stayline VPN

Thanks for helping. Bug reports, fixes, documentation and testing against different FortiGate setups are all welcome.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Security problems: please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development setup

See [docs/building.md](docs/building.md) for requirements and how to run the service and app from a build. Before opening a pull request, run:

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs the same checks on every pull request.

## Guidelines

- **Keep it small.** Stayline VPN aims to stay under ~30 MB of RAM and to do one job well. Discuss new dependencies in the issue first.
- **Platform code stays out of `stayline-core`.** Windows-specific code belongs in `stayline-net`, `stayline-svc` or `stayline-tray`.
- **No real company data.** Use `vpn.example.com`, `Example VPN`, `alice` and made-up fingerprints in code, tests, docs, screenshots and commit messages. Never include real gateway addresses, certificate pins, usernames or logs from a real network.
- **Tests:** protocol and config changes should come with unit tests.
- **Docs:** update `README.md`, `docs/` and `CHANGELOG.md` (under *Unreleased*) when behaviour changes.

## Commits and pull requests

- Write commit messages in the imperative, describing what changes for the user ("Ask for the password when a profile has none").
- Keep pull requests focused on one change and fill in the template.
- Dependency updates from Dependabot are reviewed like any other change.

## Licence

Unless you explicitly state otherwise, any contribution you submit for inclusion in Stayline VPN is dual licensed under the [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE) licences, without any additional terms or conditions.
