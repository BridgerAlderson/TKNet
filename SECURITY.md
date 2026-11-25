# Security reporting

Use GitHub's **Security → Report a vulnerability** when private vulnerability
reporting is enabled for this repository. If the button is unavailable, contact
the repository owner through a private channel listed on their GitHub profile.
Do not post credentials, private scan results or sensitive reproduction details
in public issues.

Include the affected version, platform, expected behavior and a minimal synthetic
example. TKNet's current development branch is maintained; older packaged builds
may not receive backports.

TKNet is intended for network inventory and SMB access inspection on networks you
are authorized to administer. Exported reports contain network metadata. Correct
credentials and denied share permissions are different conditions; domain policy,
wrong passwords and file-manager credential caches remain relevant to account
lockout behavior. See [SMB behavior](docs/SMB_DOLPHIN.md).
