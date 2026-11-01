# 1. Model how systemd loads a unit, not the file

Status: accepted

## Context

A systemd service is rarely one file. systemd finds the unit file first on its search path
(`/etc`, `/run`, `/usr/local/lib`, `/usr/lib`, in that order), then applies every drop-in that
matches: the unit's own `foo.service.d/`, a template's `foo@.service.d/`, prefix directories
for dashed names (`a-b-.service.d/`, `a-.service.d/`), and the type-wide `service.d/`. A
drop-in in a higher-priority directory hides one of the same name in a lower one, and
drop-ins apply in file name order. `systemctl edit` writes an `override.conf` there, which is
how most local changes are made.

The rules for combining lines are not uniform either:

- Most settings: the last line wins. An empty line resets some (`User=`, `ProtectSystem=`)
  and is ignored as invalid by others (`NoNewPrivileges=`, `UMask=`).
- A line systemd cannot read is logged and ignored, so the value before it stays.
  `ProtectSystem=strict` followed by `ProtectSystem=banana` is still strict.
- `CapabilityBoundingSet=` and `AmbientCapabilities=` merge across lines, `~` subtracts, and
  a line replaces the set instead of merging when the set is still at its default. For
  ambient capabilities that default is "none", so `~CAP_SYS_ADMIN` on an empty ambient set
  grants every capability except one.
- `RestrictAddressFamilies=` is an allow list or a `~` deny list, decided by its first line;
  lines of the other kind take entries back out.
- `DynamicUser=yes` makes systemd force `ProtectSystem=strict`, `ProtectHome=read-only` (when
  it was `no`), `PrivateTmp`, `NoNewPrivileges` and `RestrictSUIDSGID` on, whatever the unit
  says, and name the user after the unit.

A checker that reads one file misses all of this. The case that matters most is a vendor
unit that is well hardened, plus an `override.conf` from a debugging session that sets
`ProtectSystem=no`: the file anyone reviews reads as hardened, and the service is not.

## Decision

Load the unit the way systemd does, then judge the result. `--root` finds units by name on
the search path under a directory (`/` for the running machine, or a mounted image), with
all the drop-in directories above. A unit file given by path gets the drop-ins in
`<file>.d/` beside it, for checking a repository before anything is installed.

Every effective value is computed with the rule systemd uses for that setting, and every
finding points at the line that decided it. A drop-in that weakens something the main file
set is a finding of its own (UW021), naming both lines.

## How it is checked

My reading of systemd's parser is a hypothesis, so CI tests it against systemd.
`scripts/differential.sh` installs the fixtures into a GitHub runner's real search path,
runs `daemon-reload`, and requires every value `unitwarden --effective` prints to equal what
`systemctl show` reports. The fixtures in `testdata/differential` exist only to ask systemd
about corner cases: ignored and resetting lines, the capability replace rule, `none` followed
by a deny list, what `DynamicUser=` implies, and two drop-ins with the same file name in
different drop-in directories. The units are never started.

## Consequences

- The tool reports what the service gets, and which line gave it that, rather than what the
  unit file says.
- `--root` on a mounted image is only as good as the image. Units generated at boot (by
  systemd generators, into `/run`) are absent from an image, and present only on a live
  machine.
- Properties set at run time with `systemctl set-property` live in `/etc/systemd/system.control`
  and `/run/systemd/transient`, which are not read.
