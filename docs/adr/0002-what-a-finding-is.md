# 2. What counts as a finding, and how serious it is

Status: accepted

## Context

`systemd-analyze security` already scores units. It checks about eighty settings, weights
each, and prints an "exposure" number from 0 to 10. Nearly every stock service scores
"UNSAFE" or "EXPOSED", and the number does not say which of the eighty matter for the service
in front of you. It also reads the unit as loaded on the machine it runs on, so it cannot
check a unit file in a repository, or a mounted image, before it is deployed.

## Decision

Report fewer things, and say what each one lets an attacker do.

- **High** is for something that hands over privilege or a secret directly: an `Exec` line
  with the `+` prefix (it runs outside `User=` and the sandbox), an executable under a
  directory other users can write (`/tmp`, `/home`, ...), a secret-like name in
  `Environment=` (any local user can read it with `systemctl show`), and dangerous ambient
  capabilities.
- **Medium** is for a missing protection that the usual escalation paths go through:
  running as root, `NoNewPrivileges` off, `ProtectSystem` and `ProtectHome` off, a root
  service keeping every capability, raw packet sockets allowed, a world-writable `UMask`, a
  drop-in undoing a protection, and a line systemd ignores.
- **Low** is for defence in depth: the rest of the sandbox switches, which are grouped into
  one finding per unit instead of one each, system call filtering, and
  `RestrictNamespaces`.

The default `--fail-on medium` therefore fails a build for the first two groups only.

Capabilities in the bounding set are reported only for services running as root. A process
with another user ID holds none of them without ambient capabilities; the bounding set only
caps what it could gain by running a program with file capabilities, and `NoNewPrivileges=`
(UW010) is the setting that stops that.

## Consequences

- A clean result is achievable: `testdata/root/usr/lib/systemd/system/uw-hardened.service`
  has no findings, and it is an ordinary unit, not a contrived one.
- Some settings `systemd-analyze security` weighs are not checked: `IPAddressDeny=`,
  `DevicePolicy=`, `ProtectProc=`, `PrivateUsers=`, `KeyringMode=`, `RemoveIPC=` and others.
  Where they matter, `systemd-analyze security` covers them.
- The secret check matches names (`PASSWORD`, `TOKEN`, `API_KEY`, ...), so it misses a
  secret under an innocent name and flags a non-secret under a suspicious one. An empty
  value is not reported.
