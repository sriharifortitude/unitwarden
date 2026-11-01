#!/usr/bin/env bash
# Compares unitwarden with systemd itself. Installs the fixture units (all named uw-*) and the
# corner cases in testdata/differential into the real search path, reloads systemd, and requires
# every property `unitwarden --effective` prints to equal what `systemctl show` reports. Needs a
# machine running systemd and sudo; GitHub's Ubuntu runners are one. The units are never
# started, and are removed afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${UNITWARDEN:-./bin/unitwarden}
tmp=$(mktemp -d)

cleanup() {
  for dir in /usr/lib/systemd/system /etc/systemd/system; do
    sudo rm -rf "$dir"/uw-*.service "$dir"/uw-*.service.d
  done
  sudo systemctl daemon-reload
  rm -rf "$tmp"
}
trap cleanup EXIT

for src in testdata/root testdata/differential; do
  for dir in usr/lib/systemd/system etc/systemd/system; do
    sudo cp -r "$src/$dir/." "/$dir/"
  done
done
sudo systemctl daemon-reload
systemctl --version | head -1

status=0
for u in uw-backup.service uw-hardened.service uw-webapp.service uw-edge.service uw-dynamic.service uw-reset.service; do
  "$BIN" --root / --effective "$u" | tail -n +2 > "$tmp/mine.txt"
  props=$(cut -d= -f1 "$tmp/mine.txt" | paste -sd, -)
  systemctl show --property="$props" "$u" > "$tmp/systemd.txt"
  python3 - "$tmp/mine.txt" "$tmp/systemd.txt" "$u" <<'PY' || status=1
import sys
mine, real, name = sys.argv[1], sys.argv[2], sys.argv[3]
def read(p):
    out = {}
    for line in open(p):
        k, _, v = line.rstrip("\n").partition("=")
        out[k] = v.strip()
    return out
m, s = read(mine), read(real)
def same(key, a, b):
    if key in ("CapabilityBoundingSet", "AmbientCapabilities"):
        if a == "all":
            caps = set(b.lower().split())
            return "cap_sys_admin" in caps and len(caps) >= 38
        return set(a.lower().split()) == set(b.lower().split())
    if key == "RestrictAddressFamilies":
        inv = lambda v: v.startswith("~")
        return inv(a) == inv(b) and set(a.lstrip("~").split()) == set(b.lstrip("~").split())
    return a == b
bad = 0
for k, v in m.items():
    if k not in s:
        print(f"{name}: systemctl show does not print {k}")
        bad += 1
    elif not same(k, v, s[k]):
        print(f"{name}: {k}\n  unitwarden: {v}\n  systemd:    {s[k]}")
        bad += 1
print(f"{name}: {len(m) - bad} properties agree, {bad} differ")
sys.exit(1 if bad else 0)
PY
done
exit $status
