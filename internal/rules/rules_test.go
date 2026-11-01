package rules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sriharifortitude/unitwarden/internal/unit"
)

const hardened = `[Service]
ExecStart=/usr/bin/sleep infinity
User=app
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallArchitectures=native
CapabilityBoundingSet=
UMask=0077
`

func run(text string) []Finding { return Check(unit.FromText("t.service", []byte(text))) }

func has(fs []Finding, id, sev, fragment string) bool {
	for _, f := range fs {
		if f.ID == id && f.Severity == sev && strings.Contains(f.Message, fragment) {
			return true
		}
	}
	return false
}

func list(fs []Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+"/"+f.Severity+": "+f.Message)
	}
	return strings.Join(out, "\n")
}

// with returns the hardened unit with one line replaced or added.
func with(key, line string) string {
	var out []string
	replaced := false
	for _, l := range strings.Split(hardened, "\n") {
		if strings.HasPrefix(l, key+"=") {
			if line != "" {
				out = append(out, line)
			}
			replaced = true
			continue
		}
		out = append(out, l)
	}
	if !replaced && line != "" {
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestAHardenedServiceIsClean(t *testing.T) {
	if fs := run(hardened); len(fs) != 0 {
		t.Fatal(list(fs))
	}
}

func TestEachWeakness(t *testing.T) {
	cases := []struct {
		key, line, id, sev, fragment string
	}{
		{"User", "", "UW001", "medium", "runs as root"},
		{"User", "User=0", "UW001", "medium", "runs as root"},
		{"ExecStart", "ExecStart=+/usr/bin/sleep infinity", "UW002", "high", "full privileges"},
		{"ExecStart", "ExecStart=/tmp/run.sh", "UW003", "high", "/tmp/"},
		{"Environment", "Environment=API_TOKEN=abc LANG=C", "UW004", "high", "API_TOKEN"},
		{"Environment", `Environment="DB_PASSWORD=x y"`, "UW004", "high", "sets DB_PASSWORD:"},
		{"NoNewPrivileges", "", "UW010", "medium", "setuid"},
		{"ProtectSystem", "ProtectSystem=full", "UW011", "low", "ProtectSystem=full"},
		{"ProtectSystem", "ProtectSystem=true", "UW011", "low", "ProtectSystem=yes"},
		{"SystemCallArchitectures", "SystemCallArchitectures=x86 x86-64", "UW018", "low", "native"},
		{"ProtectSystem", "", "UW011", "medium", "is not set"},
		{"ProtectSystem", "ProtectSystem=no", "UW011", "medium", "ProtectSystem=no"},
		{"ProtectHome", "ProtectHome=no", "UW012", "medium", "home directory"},
		{"RestrictAddressFamilies", "", "UW017", "low", "any kind of socket"},
		{"RestrictAddressFamilies", "RestrictAddressFamilies=~AF_NETLINK", "UW017", "medium", "AF_PACKET"},
		{"SystemCallFilter", "", "UW018", "low", "SystemCallFilter"},
		{"SystemCallArchitectures", "", "UW018", "low", "native"},
		{"PrivateTmp", "PrivateTmp=no", "UW019", "low", "PrivateTmp"},
		{"RestrictNamespaces", "", "UW019", "low", "namespaces"},
		{"UMask", "UMask=0000", "UW020", "medium", "every user write"},
		{"UMask", "UMask=0020", "UW020", "medium", "every user write"},
		{"UMask", "UMask=banana", "UW020", "medium", "not an octal"},
		{"PrivateDevices", "PrivateDevices=sometimes", "UW032", "medium", "not a value systemd accepts"},
		{"AmbientCapabilities", "AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_BIND_SERVICE", "UW016", "high", "cap_sys_admin"},
	}
	for _, c := range cases {
		fs := run(with(c.key, c.line))
		if !has(fs, c.id, c.sev, c.fragment) {
			t.Errorf("%s=%q: want %s/%s %q, got\n%s", c.key, c.line, c.id, c.sev, c.fragment, list(fs))
		}
	}
}

func TestSafeVariants(t *testing.T) {
	for _, c := range []struct{ key, line string }{
		{"ExecStart", "ExecStart=-/usr/bin/sleep infinity"},
		{"ExecStart", "ExecStart=!!/usr/bin/sleep infinity"},
		{"Environment", "Environment=LANG=C TZ=UTC"},
		{"Environment", "Environment=PASSWORD_FILE="},
		{"UMask", "UMask=0027"},
		{"RestrictAddressFamilies", "RestrictAddressFamilies=~AF_PACKET AF_NETLINK"},
		{"RestrictAddressFamilies", "PrivateNetwork=yes"},
		{"AmbientCapabilities", "AmbientCapabilities=CAP_NET_BIND_SERVICE"},
		{"ProtectHome", "ProtectHome=read-only"},
	} {
		line := c.line
		text := with(c.key, line)
		if c.key == "RestrictAddressFamilies" && strings.HasPrefix(line, "PrivateNetwork") {
			text = with(c.key, "") + "\n" + line
		}
		if fs := run(text); len(fs) != 0 {
			t.Errorf("%s: %s", line, list(fs))
		}
	}
}

func TestRootServicesAndCapabilities(t *testing.T) {
	root := strings.Replace(with("CapabilityBoundingSet", ""), "User=app\n", "", 1)
	if fs := run(root); !has(fs, "UW016", "medium", "keeps every capability") || !has(fs, "UW001", "medium", "") {
		t.Fatal(list(fs))
	}
	kept := strings.Replace(with("CapabilityBoundingSet", "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN"), "User=app\n", "User=root\n", 1)
	if fs := run(kept); !has(fs, "UW016", "medium", "cap_sys_admin") {
		t.Fatal(list(fs))
	}
	if fs := run(with("CapabilityBoundingSet", "CapabilityBoundingSet=CAP_SYS_ADMIN")); has(fs, "UW016", "medium", "") {
		t.Fatal("a user other than root cannot use bounding-set capabilities it is not granted:", list(fs))
	}
}

func TestDynamicUserImpliesProtections(t *testing.T) {
	// systemd forces these on for DynamicUser=yes, whatever the unit says.
	text := strings.Replace(hardened, "User=app\n", "DynamicUser=yes\nProtectSystem=no\nProtectHome=no\nPrivateTmp=no\n", 1)
	for _, k := range []string{"NoNewPrivileges", "RestrictSUIDSGID"} {
		text = without(text, k)
	}
	if fs := run(text); len(fs) != 0 {
		t.Fatal(list(fs))
	}
}

// without removes every line setting key from text.
func without(text, key string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if !strings.HasPrefix(l, key+"=") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestInvalidLinesKeepTheEarlierValue(t *testing.T) {
	fs := run(hardened + "ProtectSystem=banana\nPrivateDevices=maybe\nUMask=9\n")
	for _, id := range []string{"UW011", "UW019"} {
		if has(fs, id, "low", "") || has(fs, id, "medium", "") {
			t.Errorf("the earlier value stays in force: %s", list(fs))
		}
	}
	if !has(fs, "UW032", "medium", "ProtectSystem=banana") || !has(fs, "UW032", "medium", "PrivateDevices=maybe") || !has(fs, "UW020", "medium", "UMask=9") {
		t.Fatal(list(fs))
	}
}

func TestMaskedAndNonServiceUnits(t *testing.T) {
	if fs := Check(&unit.Unit{Name: "x.service", Masked: true}); len(fs) != 1 || fs[0].ID != "UW031" {
		t.Fatal(fs)
	}
	if fs := Check(unit.FromText("x.socket", []byte("[Socket]\nListenStream=80\n"))); len(fs) != 0 {
		t.Fatal(fs)
	}
	if fs := Check(unit.FromText("x.service", []byte("stray\n"+hardened))); !has(fs, "UW030", "info", "") {
		t.Fatal(list(fs))
	}
}

func TestADropInThatWeakensIsReported(t *testing.T) {
	for _, c := range []struct {
		main, dropin string
		weakened     []string
	}{
		{hardened, "ProtectSystem=full\nPrivateTmp=no\nProtectHome=yes\n", []string{"PrivateTmp", "ProtectSystem"}},
		{with("ProtectSystem", "ProtectSystem=full"), "ProtectSystem=yes\n", []string{"ProtectSystem"}},
		{with("ProtectHome", "ProtectHome=read-only"), "ProtectHome=yes\nPrivateNetwork=yes\n", nil},
	} {
		dir := t.TempDir()
		main := filepath.Join(dir, "app.service")
		if err := os.WriteFile(main, []byte(c.main), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(main+".d", 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(main+".d", "debug.conf"), []byte("[Service]\n"+c.dropin), 0o600); err != nil {
			t.Fatal(err)
		}
		u, err := unit.LoadFile(main)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range Check(u) {
			if f.ID == "UW021" {
				got = append(got, strings.SplitN(f.Message, "=", 2)[0])
				if !strings.HasSuffix(f.File, "debug.conf") {
					t.Errorf("points at the drop-in: %+v", f)
				}
			}
		}
		sort.Strings(got)
		if strings.Join(got, " ") != strings.Join(c.weakened, " ") {
			t.Errorf("%q: weakened %v, want %v", c.dropin, got, c.weakened)
		}
	}
}
