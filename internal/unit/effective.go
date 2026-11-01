package unit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Get returns the value in force for a single-valued setting: the last assignment, or the
// default when there is none or the last one is empty (an empty assignment resets).
func (u *Unit) Get(section, key, def string) (string, *Assignment) {
	var last *Assignment
	for i := range u.Assignments {
		a := &u.Assignments[i]
		if a.Section == section && a.Key == key {
			last = a
		}
	}
	if last == nil || last.Value == "" {
		return def, last
	}
	return last.Value, last
}

// GetBool is Get for a boolean setting. systemd ignores a line it cannot read as a boolean, an
// empty one included, so the value before that line stays in force.
func (u *Unit) GetBool(section, key string, def bool) (bool, *Assignment) {
	v, a := u.getValid(section, key, "", func(s string) bool { _, ok := Bool(s); return ok })
	if v == "" {
		return def, a
	}
	b, _ := Bool(v)
	return b, a
}

// getValid is Get for a setting systemd checks: it skips the lines valid rejects, as systemd
// logs and ignores those. An empty line is skipped too: for booleans, ProtectSystem=,
// ProtectHome= and UMask=, systemd treats it as unreadable rather than as a reset.
func (u *Unit) getValid(section, key, def string, valid func(string) bool) (string, *Assignment) {
	v, from := def, (*Assignment)(nil)
	for i := range u.Assignments {
		a := &u.Assignments[i]
		if a.Section == section && a.Key == key && a.Value != "" && valid(a.Value) {
			v, from = a.Value, a
		}
	}
	return v, from
}

// boundingRemovals are the capabilities systemd takes out of the bounding set when a
// protection is on (unit_patch_contexts in src/core/unit.c).
var boundingRemovals = []struct {
	key  string
	caps []string
}{
	{"PrivateDevices", []string{"cap_mknod", "cap_sys_rawio"}},
	{"ProtectClock", []string{"cap_sys_time", "cap_wake_alarm"}},
	{"ProtectKernelModules", []string{"cap_sys_module"}},
	{"ProtectKernelLogs", []string{"cap_syslog"}},
}

// ValidProtectSystem reports whether systemd accepts a ProtectSystem= value.
func ValidProtectSystem(s string) bool {
	_, ok := Bool(s)
	return ok || s == "full" || s == "strict"
}

// ValidProtectHome reports whether systemd accepts a ProtectHome= value.
func ValidProtectHome(s string) bool {
	_, ok := Bool(s)
	return ok || s == "read-only" || s == "tmpfs"
}

// ValidMode reports whether systemd accepts a UMask= value: octal, at most 07777.
func ValidMode(s string) bool {
	n, err := strconv.ParseUint(s, 8, 32)
	return err == nil && n <= 0o7777
}

// Dynamic reports whether DynamicUser= is on. systemd then turns several protections on when it
// loads the unit (unit_patch_contexts in src/core/unit.c), and systemctl show reports them on.
func (u *Unit) Dynamic() bool {
	b, _ := u.GetBool("Service", "DynamicUser", false)
	return b
}

// CapSet is the effective value of a capability setting.
type CapSet struct {
	// All is true when the setting leaves every capability in place.
	All  bool
	Caps map[string]bool
	// From is the last assignment that changed the set.
	From *Assignment
}

// Has reports whether a capability (any case, with or without the CAP_ prefix) is in the set.
func (c CapSet) Has(name string) bool {
	if c.All {
		return true
	}
	return c.Caps[normCap(name)]
}

func normCap(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "cap_") {
		s = "cap_" + s
	}
	return s
}

// Capabilities evaluates CapabilityBoundingSet= (unset means every capability) or
// AmbientCapabilities= (unset means none) the way config_parse_capability_set does. A line
// replaces the set when it lists nothing ("" is no capabilities, "~" is all of them) or when the
// set is still untouched; otherwise lines merge, and a "~" line removes what it lists. Ambient
// capabilities count as untouched whenever the set is empty again, so "~CAP_X" on an empty
// ambient set grants everything except CAP_X. systemd then removes a few capabilities from the
// bounding set for PrivateDevices=, ProtectClock=, ProtectKernelModules= and ProtectKernelLogs=.
func (u *Unit) Capabilities(key string) CapSet {
	set := u.capabilityLines(key)
	if key != "CapabilityBoundingSet" {
		return set
	}
	for _, r := range boundingRemovals {
		if on, _ := u.GetBool("Service", r.key, false); on {
			if set.All {
				set.All, set.Caps = false, allCaps()
			}
			for _, c := range r.caps {
				delete(set.Caps, c)
			}
		}
	}
	return set
}

func (u *Unit) capabilityLines(key string) CapSet {
	bounding := key == "CapabilityBoundingSet"
	set := CapSet{All: bounding, Caps: map[string]bool{}}
	untouched := true
	for i := range u.Assignments {
		a := &u.Assignments[i]
		if a.Section != "Service" || a.Key != key {
			continue
		}
		invert := strings.HasPrefix(a.Value, "~")
		names := strings.Fields(strings.TrimPrefix(a.Value, "~"))
		replace := len(names) == 0 || (bounding && untouched) || (!bounding && !set.All && len(set.Caps) == 0)
		untouched = false
		set.From = a
		switch {
		case replace && invert:
			set.All, set.Caps = len(names) == 0, map[string]bool{}
			if !set.All {
				set.Caps = allCaps()
			}
		case replace:
			set.All, set.Caps = false, map[string]bool{}
		case invert && set.All:
			set.All, set.Caps = false, allCaps()
		}
		if set.All {
			continue
		}
		for _, n := range names {
			if invert {
				delete(set.Caps, normCap(n))
			} else {
				set.Caps[normCap(n)] = true
			}
		}
	}
	return set
}

// Families is the effective RestrictAddressFamilies=.
type Families struct {
	Set bool
	// Deny is true for a "~" list: everything except these. Otherwise only these are allowed.
	Deny bool
	List map[string]bool
	From *Assignment
	// started is false until a line with families in it begins a list; "none" does not.
	started bool
}

// AddressFamilies evaluates RestrictAddressFamilies= the way config_parse_address_families
// does: the first line with families in it decides between an allow list and a "~" deny list,
// later lines of the same kind add to it and lines of the other kind take families back out.
// "none" allows nothing (a later line starts a fresh list), and an empty line undoes it all.
func (u *Unit) AddressFamilies() Families {
	f := Families{List: map[string]bool{}}
	for i := range u.Assignments {
		a := &u.Assignments[i]
		if a.Section != "Service" || a.Key != "RestrictAddressFamilies" {
			continue
		}
		f.From = a
		v := a.Value
		if v == "" {
			f = Families{List: map[string]bool{}, From: a}
			continue
		}
		if v == "none" {
			f = Families{Set: true, List: map[string]bool{}, From: a}
			continue
		}
		deny := strings.HasPrefix(v, "~")
		names := strings.Fields(strings.TrimPrefix(v, "~"))
		switch {
		case !f.started:
			f.Set, f.Deny, f.started = true, deny, true
			for _, n := range names {
				f.List[strings.ToUpper(n)] = true
			}
		case f.Deny == deny:
			for _, n := range names {
				f.List[strings.ToUpper(n)] = true
			}
		default:
			// An allow line after a deny list (or the reverse) takes those families back out.
			for _, n := range names {
				delete(f.List, strings.ToUpper(n))
			}
		}
	}
	return f
}

// Allows reports whether an address family can be used.
func (f Families) Allows(af string) bool {
	if !f.Set {
		return true
	}
	return f.List[af] != f.Deny
}

// Command is one Exec*= line with its prefixes taken apart.
type Command struct {
	Path string
	Args string
	// Prefixes holds any of "-", "@", ":", "+", "!", "!!".
	Prefixes string
	From     *Assignment
}

// Commands returns the effective list for an Exec*= key; an empty assignment clears the list.
func (u *Unit) Commands(key string) []Command {
	var out []Command
	for i := range u.Assignments {
		a := &u.Assignments[i]
		if a.Section != "Service" || a.Key != key {
			continue
		}
		if a.Value == "" {
			out = nil
			continue
		}
		v := a.Value
		j := 0
		for j < len(v) && strings.ContainsRune("-@:+!", rune(v[j])) {
			j++
		}
		rest := strings.TrimSpace(v[j:])
		path, args, _ := strings.Cut(rest, " ")
		out = append(out, Command{Path: path, Args: strings.TrimSpace(args), Prefixes: v[:j], From: a})
	}
	return out
}

// allCaps lists the capabilities Linux defines (capability.h, as of 6.x), lower-case.
func allCaps() map[string]bool {
	m := map[string]bool{}
	for _, c := range []string{"chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid",
		"setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
		"sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
		"sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap",
		"mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
		"checkpoint_restore"} {
		m["cap_"+c] = true
	}
	return m
}

// EffectiveKeys are the properties --effective prints, in systemctl show's spelling.
var EffectiveKeys = []string{
	"User", "DynamicUser", "NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices",
	"PrivateNetwork", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups",
	"ProtectClock", "ProtectHostname", "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality",
	"MemoryDenyWriteExecute", "CapabilityBoundingSet", "AmbientCapabilities", "RestrictAddressFamilies", "UMask",
}

// Effective returns the value of an EffectiveKeys property as systemctl show would print it,
// except that a full capability set is written "all".
func (u *Unit) Effective(key string) string {
	v, _ := u.Value(key)
	return v
}

// Value is Effective with the assignment that decided the value: the last line systemd used, the
// DynamicUser= line for a protection it implies, or nil for a default.
func (u *Unit) Value(key string) (string, *Assignment) {
	yesNo := map[bool]string{true: "yes", false: "no"}
	dynamic, dyn := u.GetBool("Service", "DynamicUser", false)
	switch key {
	case "User":
		v, a := u.Get("Service", "User", "")
		if v == "" && dynamic {
			return dynamicUserName(u.Name), dyn
		}
		return v, a
	case "ProtectSystem", "ProtectHome":
		valid := ValidProtectSystem
		if key == "ProtectHome" {
			valid = ValidProtectHome
		}
		v, a := u.getValid("Service", key, "no", valid)
		if b, ok := Bool(v); ok {
			v = yesNo[b]
		}
		switch {
		case dynamic && key == "ProtectSystem":
			return "strict", dyn
		case dynamic && v == "no":
			return "read-only", dyn
		}
		return v, a
	case "CapabilityBoundingSet", "AmbientCapabilities":
		c := u.Capabilities(key)
		if c.All {
			return "all", c.From
		}
		return joinSorted(c.Caps), c.From
	case "RestrictAddressFamilies":
		f := u.AddressFamilies()
		switch {
		case !f.Set:
			return "~", f.From
		case !f.Deny && len(f.List) == 0:
			return "none", f.From
		case f.Deny:
			return "~" + joinSorted(f.List), f.From
		}
		return joinSorted(f.List), f.From
	case "UMask":
		v, a := u.getValid("Service", "UMask", "0022", ValidMode)
		n, _ := strconv.ParseUint(v, 8, 32)
		return fmt.Sprintf("%04o", n), a
	case "PrivateTmp", "NoNewPrivileges", "RestrictSUIDSGID":
		if dynamic {
			return "yes", dyn
		}
	}
	b, a := u.GetBool("Service", key, false)
	return yesNo[b], a
}

// dynamicUserName is the user name systemd picks for DynamicUser=yes without User=: the unit
// name's prefix, when that is a valid user name. Otherwise systemd hashes it into "_du" and 16
// hex digits, which this does not reproduce, and returns "".
func dynamicUserName(unit string) string {
	prefix := unit
	if i := strings.IndexByte(prefix, '@'); i >= 0 {
		prefix = prefix[:i]
	} else if i := strings.LastIndexByte(prefix, '.'); i >= 0 {
		prefix = prefix[:i]
	}
	if len(prefix) == 0 || len(prefix) > 31 {
		return ""
	}
	for i, r := range prefix {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_'
		if !letter && (i == 0 || !(r >= '0' && r <= '9' || r == '-')) {
			return ""
		}
	}
	return prefix
}

func joinSorted(m map[string]bool) string {
	var xs []string
	for k := range m {
		xs = append(xs, k)
	}
	sort.Strings(xs)
	return strings.Join(xs, " ")
}
