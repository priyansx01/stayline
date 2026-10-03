# Security policy

Stayline VPN handles credentials and network traffic, so security reports are taken seriously.

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Please **do not** open a public issue. Report it privately through GitHub: go to the repository's **Security** tab and choose **Report a vulnerability**.

Include:
- the version of Stayline VPN and of Windows,
- what an attacker could do and what they need (local user, network position, …),
- steps to reproduce or a proof of concept,
- any logs, with gateway addresses, usernames and other identifying details removed.

You will get an acknowledgement within a week. Once a fix is ready it is released and the advisory published, crediting you unless you prefer otherwise.

## Scope

In scope: the service, the app, the installer, certificate validation and pinning, the named-pipe interface, storage of saved passwords, and anything that lets one Windows user affect another user's connection or credentials.

Out of scope: vulnerabilities in FortiGate itself, and problems that require an attacker who is already an administrator on the machine.
