# unitwarden

[![CI](https://github.com/sriharifortitude/unitwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/unitwarden/actions/workflows/ci.yml)

Judges how much a systemd service could do if it were compromised. It loads a unit the way
systemd does (the search path, every drop-in directory that applies, the rule each setting
follows when lines repeat) and reports what the service actually gets, pointing at the line
that gave it. Go, standard library only, MIT.

## What it is for

A vendor ships a well-hardened unit. Months later someone runs `systemctl edit` to debug a
permissions problem, and an `override.conf` turns `ProtectSystem` off and runs one command
with the `+` prefix, outside the sandbox. The unit file in `/usr/lib` still reads as
hardened; the service is not. unitwarden reads both, in systemd's order:

<!-- demo:start -->
```
$ unitwarden --root testdata/root
uw-backup.service
  UW003 high     ExecStart runs /home/backup/bin/run-backup.sh, from /home/, where another user may be able to replace it  (testdata/root/usr/lib/systemd/system/uw-backup.service:6)
  UW001 medium   runs as root: neither User= (other than root) nor DynamicUser=yes is set
  UW011 medium   ProtectSystem is not set: the service can write /usr, /boot and /etc
  UW012 medium   ProtectHome is not set: the service can read every user's home directory
  UW016 medium   CapabilityBoundingSet is not limited and the service runs as root: it keeps every capability
  UW017 low      RestrictAddressFamilies is not set: the service can open any kind of socket, raw packet sockets included
  UW018 low      system calls are not limited: set SystemCallFilter= (for example @system-service) and SystemCallArchitectures=native
  UW019 low      12 sandbox setting(s) are off: PrivateTmp, PrivateDevices, ProtectKernelTunables, ProtectKernelModules, ProtectKernelLogs, ProtectControlGroups, ProtectClock, ProtectHostname, RestrictRealtime, RestrictSUIDSGID, LockPersonality, MemoryDenyWriteExecute
  UW019 low      RestrictNamespaces is not set: the service can create namespaces, a common step in container escapes

uw-webapp.service
  UW002 high     ExecStartPre=+/usr/bin/chown runs with full privileges: the + prefix ignores User=, the sandbox and capability limits for this command  (testdata/root/etc/systemd/system/uw-webapp.service.d/override.conf:4)
  UW004 high     Environment= sets DB_PASSWORD: unit properties, environment included, can be read by any local user with systemctl show; use LoadCredential= or an EnvironmentFile= readable only by root  (testdata/root/etc/systemd/system/uw-webapp.service.d/override.conf:5)
  UW011 medium   ProtectSystem=no: the service can write /usr, /boot and /etc  (testdata/root/etc/systemd/system/uw-webapp.service.d/override.conf:3)
  UW021 medium   ProtectSystem=no in this drop-in undoes ProtectSystem=strict from testdata/root/usr/lib/systemd/system/uw-webapp.service:9: the unit file reads as hardened, the service is not  (testdata/root/etc/systemd/system/uw-webapp.service.d/override.conf:3)
  UW018 low      system calls are not limited: set SystemCallFilter= (for example @system-service) and SystemCallArchitectures=native
  UW019 low      10 sandbox setting(s) are off: ProtectKernelTunables, ProtectKernelModules, ProtectKernelLogs, ProtectControlGroups, ProtectClock, ProtectHostname, RestrictRealtime, RestrictSUIDSGID, LockPersonality, MemoryDenyWriteExecute
  UW019 low      RestrictNamespaces is not set: the service can create namespaces, a common step in container escapes

3 unit(s); 3 high, 6 medium, 7 low

$ unitwarden --root testdata/root --effective uw-webapp.service
# uw-webapp.service
User=www-data
DynamicUser=no
NoNewPrivileges=yes
ProtectSystem=no
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=no
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectKernelLogs=no
ProtectControlGroups=no
ProtectClock=no
ProtectHostname=no
RestrictRealtime=no
RestrictSUIDSGID=no
LockPersonality=no
MemoryDenyWriteExecute=no
CapabilityBoundingSet=cap_net_bind_service
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0022
```
<!-- demo:end -->

`uw-webapp.service` sets `ProtectSystem=strict` in its own file, and the drop-in undoes it
(UW021 names both lines). `uw-backup.service` runs as root, from a script in a home
directory. A third fixture, `uw-hardened.service`, has no findings and is not listed.
`--effective` prints what is in force with `systemctl show`'s names and spellings, which is
also what CI compares with a real systemd.

## Usage

```bash
go install github.com/sriharifortitude/unitwarden/cmd/unitwarden@v0.1.1

unitwarden --root /                          # every service on this machine
unitwarden --root / nginx.service ssh.service
unitwarden --root /mnt/image                 # a mounted image or a copy of another machine
unitwarden deploy/myapp.service              # a file in a repository, with deploy/myapp.service.d/*.conf
unitwarden --effective --root / myapp.service
```

Exit codes: 0 nothing at or above `--fail-on` (default medium), 1 at least one finding is,
2 a usage error or an unreadable file. `--json` gives the findings with file and line.

## How it reads a unit

- **Search path**: `/etc/systemd/system`, `/run/systemd/system`,
  `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system`; the
  first unit file found wins, and a link to `/dev/null` means masked.
- **Drop-ins**: `foo.service.d/`, the template's `foo@.service.d/`, the prefix directories of
  a dashed name (`a-b-.service.d/`, `a-.service.d/`) and `service.d/`, in every directory of
  the search path. A drop-in hides one of the same file name in a lower-priority directory,
  even when the hidden one is in a more specific drop-in directory; all of them apply in file
  name order.
- **Repeated lines**: the last valid line wins. A line systemd cannot read is ignored and
  the earlier value stays. An empty line resets `User=` and is ignored for the protection
  settings and `UMask=`. Capability sets and address families merge across lines with `~`
  subtracting, including systemd's rule for when a line replaces the set instead of merging.
- **Implied settings**: `DynamicUser=yes` forces `ProtectSystem=strict`,
  `ProtectHome=read-only` (when it was `no`), `PrivateTmp`, `NoNewPrivileges` and
  `RestrictSUIDSGID` on. `PrivateDevices`, `ProtectClock`, `ProtectKernelModules` and
  `ProtectKernelLogs` take their capabilities out of the bounding set.

[ADR 1](docs/adr/0001-model-systemds-loading-not-the-file.md) has the reasoning and the
corner cases.

## Checks

| ID | Severity | What it finds |
|---|---|---|
| UW001 | medium | runs as root: no `User=` other than root, and no `DynamicUser=yes` |
| UW002 | high | an `Exec*=` line with the `+` prefix, which ignores `User=`, the sandbox and capability limits |
| UW003 | high | an executable under `/tmp`, `/var/tmp`, `/dev/shm`, `/home` or `/run/user` |
| UW004 | high | `Environment=` setting a name like `PASSWORD`, `TOKEN` or `API_KEY`: `systemctl show` prints it to any local user |
| UW010 | medium | `NoNewPrivileges` off: setuid programs can raise the service's privileges |
| UW011 | medium / low | `ProtectSystem` off (medium), or `yes`/`full` rather than `strict` (low) |
| UW012 | medium | `ProtectHome` off |
| UW016 | high / medium | dangerous ambient capabilities (high); a root service keeping every capability, or `CAP_SYS_ADMIN`, `CAP_SYS_MODULE` or `CAP_SYS_PTRACE` (medium) |
| UW017 | medium / low | `AF_PACKET` allowed (medium); `RestrictAddressFamilies` not set (low) |
| UW018 | low | no `SystemCallFilter=`, or `SystemCallArchitectures` not `native` |
| UW019 | low | the other sandbox switches that are off, as one finding; `RestrictNamespaces` not set |
| UW020 | medium | a `UMask` that lets every user write the service's files, or one systemd cannot read |
| UW021 | medium | a drop-in weakening a protection the unit file sets |
| UW030 | info | a line systemd ignores: no section, no `=`, an unclosed section header |
| UW031 | info | the unit is masked |
| UW032 | medium | a value systemd does not accept for a protection setting, so the line does nothing |

[ADR 2](docs/adr/0002-what-a-finding-is.md) explains the severities, and what is left to
`systemd-analyze security`.

## Tested

```bash
go test ./...                    # unit, rule and CLI tests, and a fuzz target for the parser
./scripts/differential.sh        # against systemd itself; needs a systemd machine and sudo
```

**Against systemd.** `scripts/differential.sh` installs every fixture into the real search
path of a machine running systemd, runs `daemon-reload`, and requires each of the 22 values
`unitwarden --effective` prints per unit to equal `systemctl show`. Three of the six units,
in `testdata/differential`, exist only to ask systemd about corner cases. There is no
systemd on the Windows machine this was written on, so this runs in CI. On systemd 259
(Ubuntu), all 132 values for the six units agree.

That took two runs, and the fixtures changed the tool before either. Working out what systemd
should print for each corner case, from what I know of its parser, showed four places where
my first model was wrong: it treated an unreadable line as resetting to the default (systemd
keeps the earlier value), it ignored everything `DynamicUser=` implies, it merged `~CAP_X`
into an empty ambient set instead of replacing the set, and it kept
`RestrictAddressFamilies=none` in force after a later deny line. The first two would have
produced false findings on ordinary units.

The first run, with five units, agreed on 105 of 110 values. The five that differed were four
more mistakes and one spelling:

- an empty `ProtectHome=` line is ignored, not a reset, so `read-only` stayed;
- a prefix drop-in in `/etc` hid the unit's own drop-in of the same name in `/usr/lib`: the
  search path decides before the drop-in directory does, the opposite of my guess;
- `PrivateDevices=yes` took `CAP_MKNOD` and `CAP_SYS_RAWIO` out of the bounding set, and
  `ProtectClock=yes` took `CAP_SYS_TIME` and `CAP_WAKE_ALARM`;
- an unset `RestrictAddressFamilies` is printed as `~`, an empty deny list.

The bounding set fix changed a rule too: a root service with `PrivateDevices=yes` and no
bounding set no longer had "every capability", and reworking UW016 for that showed an
explicit `CapabilityBoundingSet=~` had never been reported. For the second run I added a sixth
unit and two drop-ins to ask what the first left open, and wrote down the answers I expected
first: an empty `ProtectSystem=` is ignored and an empty `User=` resets, `ProtectKernelModules=`
and `ProtectKernelLogs=` take `CAP_SYS_MODULE` and `CAP_SYSLOG` out, and inside one directory
the unit's own drop-in beats a prefix drop-in of the same name. All of them held.

**Mutation testing.** I broke the code on purpose, 50 ways at first. On the first run, 12
mutants survived, 6 did not compile (I rewrote them so they do) and 1 did not match the
source. One survivor marked a redundant check in UW021, which I deleted along with its mutant.
The others were test gaps: continuation lines were checked with `Contains`, so a kept
backslash passed; the drop-in order test set a different key in each file, so order never
mattered; a name on the search path twice, a `~` line after `CapabilityBoundingSet=~`,
`User=0`, `ProtectSystem=yes`, a 32-bit system call architecture and a quoted `Environment=`
name were untested; and no drop-in test had one going from `full` to `yes`, or one that
strengthens a setting. The rewritten mutants found two more: a `UMask` that blocks group
writes but not world writes, and one above 07777, which systemd rejects. After the systemd
fixes I added mutants for the new code (56 in all), and one more gap showed:
`AmbientCapabilities=~` alone, which grants everything. All 56 are caught now except one:
masking is detected through a symlink to `/dev/null`, Windows would not let the test create
one, so that test skips here and runs only on Linux.

## Not tested, and not done

- Only systemd 259 has been compared. Older releases, such as 249 in Ubuntu 22.04, parse some
  of these settings differently, and the model follows 259.
- Units generated at boot by systemd generators, and properties set with
  `systemctl set-property`, are not read: they live outside the unit search path.
- User units (`systemctl --user`) and their search path are not supported.
- Specifiers such as `%h` and `%i` are not expanded, so an `ExecStart=` path that uses one is
  not checked against the writable directories.
- `systemd-analyze security` covers many settings this does not check; ADR 2 lists them.
