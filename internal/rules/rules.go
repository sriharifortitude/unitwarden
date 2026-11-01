// Package rules judges how much a systemd service can do if it is compromised.
package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sriharifortitude/unitwarden/internal/unit"
)

// Severities, most serious first.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// Rank orders severities: critical is 0.
func Rank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return len(Severities)
}

// Finding is one problem with one unit.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Unit     string `json:"unit"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message"`
}

type checker struct {
	u   *unit.Unit
	out []Finding
}

func (c *checker) add(id, sev string, at *unit.Assignment, format string, args ...any) {
	f := Finding{ID: id, Severity: sev, Unit: c.u.Name, Message: fmt.Sprintf(format, args...)}
	if at != nil {
		f.File, f.Line = at.File, at.Line
	} else if c.u.Path != "" {
		f.File = c.u.Path
	}
	c.out = append(c.out, f)
}

var secretName = regexp.MustCompile(`(?i)(password|passwd|secret|token|api_?key|private_?key|credential)`)

var writableDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/"}

// dangerousCaps give a process ways around most other protections.
var dangerousCaps = map[string]string{
	"cap_sys_admin":       "almost everything root can do",
	"cap_sys_module":      "loading kernel modules",
	"cap_sys_ptrace":      "reading and changing other processes",
	"cap_sys_rawio":       "raw I/O on devices and memory",
	"cap_dac_override":    "ignoring file permissions",
	"cap_dac_read_search": "reading any file",
	"cap_net_admin":       "reconfiguring the network",
	"cap_bpf":             "loading BPF programs",
	"cap_sys_boot":        "rebooting the machine",
	"cap_mac_admin":       "changing the MAC policy",
	"cap_mac_override":    "ignoring the MAC policy",
	"cap_setuid":          "becoming any user",
}

// booleanProtections are the yes/no sandbox settings, with what each one stops.
var booleanProtections = []struct{ key, why string }{
	{"NoNewPrivileges", "setuid programs and file capabilities can raise its privileges"},
	{"PrivateTmp", "it shares /tmp with every other process"},
	{"PrivateDevices", "it can open device nodes"},
	{"ProtectKernelTunables", "it can write /proc/sys and /sys"},
	{"ProtectKernelModules", "it can load kernel modules"},
	{"ProtectKernelLogs", "it can read the kernel log"},
	{"ProtectControlGroups", "it can write the cgroup tree"},
	{"ProtectClock", "it can set the system clock"},
	{"ProtectHostname", "it can change the host name"},
	{"RestrictRealtime", "it can take realtime scheduling and starve the machine"},
	{"RestrictSUIDSGID", "it can create setuid and setgid files"},
	{"LockPersonality", "it can change its execution domain"},
	{"MemoryDenyWriteExecute", "it can create memory that is both writable and executable"},
}

// Check judges one unit.
func Check(u *unit.Unit) []Finding {
	c := &checker{u: u}
	for _, p := range u.Problems {
		c.out = append(c.out, Finding{ID: "UW030", Severity: "info", Unit: u.Name, File: p.File, Line: p.Line, Message: p.Message})
	}
	if u.Masked {
		c.add("UW031", "info", nil, "the unit is masked (linked to /dev/null): it cannot be started")
		return c.out
	}
	if u.Type() != "service" {
		return c.out
	}
	c.unreadableBooleans()
	c.identity()
	c.commands()
	c.environment()
	c.filesystem()
	c.capabilities()
	c.network()
	c.syscalls()
	c.smallProtections()
	c.umask()
	c.weakenedByDropIn()
	sort.SliceStable(c.out, func(i, j int) bool {
		if Rank(c.out[i].Severity) != Rank(c.out[j].Severity) {
			return Rank(c.out[i].Severity) < Rank(c.out[j].Severity)
		}
		return c.out[i].ID < c.out[j].ID
	})
	return c.out
}

func (c *checker) runsAsRoot() bool {
	user, _ := c.u.Get("Service", "User", "")
	dynamic, _ := c.u.GetBool("Service", "DynamicUser", false)
	return !dynamic && (user == "" || user == "root" || user == "0")
}

func (c *checker) unreadableBooleans() {
	keys := []string{"DynamicUser", "ProtectSystem", "ProtectHome"}
	for _, p := range booleanProtections {
		keys = append(keys, p.key)
	}
	valid := func(k, v string) bool {
		switch k {
		case "ProtectSystem":
			return unit.ValidProtectSystem(v)
		case "ProtectHome":
			return unit.ValidProtectHome(v)
		}
		_, ok := unit.Bool(v)
		return ok
	}
	for i := range c.u.Assignments {
		a := &c.u.Assignments[i]
		if a.Section == "Service" && a.Value != "" && containsKey(keys, a.Key) && !valid(a.Key, a.Value) {
			c.add("UW032", "medium", a, "%s=%s is not a value systemd accepts: it ignores the line, and the setting stays as it was before it", a.Key, a.Value)
		}
	}
}

func (c *checker) identity() {
	if c.runsAsRoot() {
		_, at := c.u.Get("Service", "User", "")
		c.add("UW001", "medium", at, "runs as root: neither User= (other than root) nor DynamicUser=yes is set")
	}
}

func (c *checker) commands() {
	for _, key := range []string{"ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"} {
		for _, cmd := range c.u.Commands(key) {
			if strings.Contains(cmd.Prefixes, "+") {
				c.add("UW002", "high", cmd.From, "%s=+%s runs with full privileges: the + prefix ignores User=, the sandbox and capability limits for this command", key, cmd.Path)
			}
			for _, dir := range writableDirs {
				if strings.HasPrefix(cmd.Path, dir) {
					c.add("UW003", "high", cmd.From, "%s runs %s, from %s, where another user may be able to replace it", key, cmd.Path, dir)
					break
				}
			}
		}
	}
}

func (c *checker) environment() {
	for i := range c.u.Assignments {
		a := &c.u.Assignments[i]
		if a.Section != "Service" || a.Key != "Environment" {
			continue
		}
		for _, kv := range strings.Fields(strings.ReplaceAll(a.Value, `"`, " ")) {
			name, value, ok := strings.Cut(kv, "=")
			if ok && value != "" && secretName.MatchString(name) {
				c.add("UW004", "high", a, "Environment= sets %s: unit properties, environment included, can be read by any local user with systemctl show; use LoadCredential= or an EnvironmentFile= readable only by root", name)
			}
		}
	}
}

func (c *checker) filesystem() {
	switch ps, a := c.u.Value("ProtectSystem"); ps {
	case "strict":
	case "full", "yes":
		c.add("UW011", "low", a, "ProtectSystem=%s leaves /var and /etc (with yes) writable; strict makes everything read-only except what ReadWritePaths= names", ps)
	default:
		c.add("UW011", "medium", a, "%s: the service can write /usr, /boot and /etc", setting("ProtectSystem", a))
	}
	if ph, a := c.u.Value("ProtectHome"); ph == "no" {
		c.add("UW012", "medium", a, "%s: the service can read every user's home directory", setting("ProtectHome", a))
	}
}

// setting describes a setting's state: "ProtectSystem=no" when a line sets it, "ProtectSystem
// is not set" when none does.
func setting(key string, a *unit.Assignment) string {
	if a != nil && a.Value != "" {
		return key + "=" + a.Value
	}
	return key + " is not set"
}

func (c *checker) capabilities() {
	bounding := c.u.Capabilities("CapabilityBoundingSet")
	ambient := c.u.Capabilities("AmbientCapabilities")
	var granted []string
	for cp, why := range dangerousCaps {
		if ambient.Has(cp) {
			granted = append(granted, cp+" ("+why+")")
		}
	}
	sort.Strings(granted)
	if len(granted) > 0 {
		c.add("UW016", "high", ambient.From, "AmbientCapabilities= grants %s", strings.Join(granted, ", "))
	}
	if !c.runsAsRoot() {
		return
	}
	switch {
	case bounding.All:
		c.add("UW016", "medium", bounding.From, "CapabilityBoundingSet is not limited and the service runs as root: it keeps every capability")
	case bounding.From == nil:
		// Not set, but PrivateDevices= and similar settings took a few capabilities out.
		c.add("UW016", "medium", nil, "CapabilityBoundingSet is not limited and the service runs as root: it keeps every capability its sandbox settings do not remove, cap_sys_admin included")
	default:
		var kept []string
		for _, cp := range []string{"cap_sys_admin", "cap_sys_module", "cap_sys_ptrace"} {
			if bounding.Has(cp) {
				kept = append(kept, cp)
			}
		}
		if len(kept) > 0 {
			c.add("UW016", "medium", bounding.From, "CapabilityBoundingSet= keeps %s, which make most other limits easy to escape", strings.Join(kept, ", "))
		}
	}
}

func (c *checker) network() {
	f := c.u.AddressFamilies()
	private, _ := c.u.GetBool("Service", "PrivateNetwork", false)
	switch {
	case private:
	case !f.Set:
		c.add("UW017", "low", nil, "RestrictAddressFamilies is not set: the service can open any kind of socket, raw packet sockets included")
	case f.Allows("AF_PACKET"):
		c.add("UW017", "medium", f.From, "RestrictAddressFamilies allows AF_PACKET: raw packet sockets can sniff and forge traffic")
	}
}

func (c *checker) syscalls() {
	filter, _ := c.u.Get("Service", "SystemCallFilter", "")
	arch, a := c.u.Get("Service", "SystemCallArchitectures", "")
	var missing []string
	if filter == "" {
		missing = append(missing, "SystemCallFilter= (for example @system-service)")
	}
	if arch != "native" {
		missing = append(missing, "SystemCallArchitectures=native")
	}
	if len(missing) > 0 {
		c.add("UW018", "low", a, "system calls are not limited: set %s", strings.Join(missing, " and "))
	}
}

func (c *checker) smallProtections() {
	var off []string
	for _, p := range booleanProtections {
		if c.u.Effective(p.key) != "yes" {
			off = append(off, p.key)
		}
	}
	if len(off) > 0 {
		sev := "low"
		if containsKey(off, "NoNewPrivileges") {
			// The one that matters most when the service is not root: it stops setuid escalation.
			c.add("UW010", "medium", nil, "NoNewPrivileges is not set: %s", booleanProtections[0].why)
			off = remove(off, "NoNewPrivileges")
		}
		if len(off) > 0 {
			c.add("UW019", sev, nil, "%d sandbox setting(s) are off: %s", len(off), strings.Join(off, ", "))
		}
	}
	if ns, _ := c.u.Get("Service", "RestrictNamespaces", ""); ns == "" {
		c.add("UW019", "low", nil, "RestrictNamespaces is not set: the service can create namespaces, a common step in container escapes")
	}
}

func containsKey(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func remove(xs []string, x string) []string {
	var out []string
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

func (c *checker) umask() {
	for i := range c.u.Assignments {
		a := &c.u.Assignments[i]
		if a.Section == "Service" && a.Key == "UMask" && a.Value != "" && !unit.ValidMode(a.Value) {
			c.add("UW020", "medium", a, "UMask=%s is not an octal mask: systemd ignores the line", a.Value)
		}
	}
	v, a := c.u.Value("UMask")
	if n, _ := strconv.ParseUint(v, 8, 32); n&0o002 == 0 {
		c.add("UW020", "medium", a, "UMask=%s lets every user write the files the service creates", v)
	}
}

// weakenedByDropIn reports a protection the main unit file turns on and a later drop-in turns
// off again: the main file reads as hardened, and the service is not. It compares what the main
// file alone would give with what the whole unit gives.
func (c *checker) weakenedByDropIn() {
	strength := func(key, v string) int {
		switch key {
		case "ProtectSystem":
			return map[string]int{"strict": 3, "full": 2, "yes": 1}[v]
		case "ProtectHome":
			return map[string]int{"yes": 2, "read-only": 1, "tmpfs": 1}[v]
		}
		return map[string]int{"yes": 1}[v]
	}
	main := &unit.Unit{Name: c.u.Name, Path: c.u.Path}
	for _, a := range c.u.Assignments {
		if a.File == c.u.Path {
			main.Assignments = append(main.Assignments, a)
		}
	}
	keys := []string{"ProtectSystem", "ProtectHome", "DynamicUser"}
	for _, p := range booleanProtections {
		keys = append(keys, p.key)
	}
	for _, k := range keys {
		was, inMain := main.Value(k)
		now, final := c.u.Value(k)
		// When the deciding line is in the main file, was and now are the same.
		if inMain == nil {
			continue
		}
		if strength(k, now) < strength(k, was) {
			c.add("UW021", "medium", final, "%s=%s in this drop-in undoes %s=%s from %s:%d: the unit file reads as hardened, the service is not",
				k, now, k, was, inMain.File, inMain.Line)
		}
	}
}
