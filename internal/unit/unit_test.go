package unit

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func text(t *testing.T, s string) *Unit {
	t.Helper()
	return FromText("t.service", []byte(s))
}

func TestParseSectionsCommentsAndContinuations(t *testing.T) {
	u := text(t, "# comment\n; also a comment\n[Unit]\nDescription = A thing\n[Service]\nExecStart=/usr/bin/a \\\n  --long \\\n# a comment inside the continuation\n  --flag\nUser=x\n")
	if len(u.Problems) != 0 {
		t.Fatal(u.Problems)
	}
	if v, _ := u.Get("Unit", "Description", ""); v != "A thing" {
		t.Fatalf("%q", v)
	}
	cmds := u.Commands("ExecStart")
	if len(cmds) != 1 || cmds[0].Path != "/usr/bin/a" || strings.Join(strings.Fields(cmds[0].Args), " ") != "--long --flag" {
		t.Fatalf("%+v", cmds)
	}
	if v, a := u.Get("Service", "User", ""); v != "x" || a.Line != 10 {
		t.Fatalf("%q %+v", v, a)
	}
}

func TestParseProblems(t *testing.T) {
	u := text(t, "User=early\n[Service\n[Service]\njust words\n")
	if len(u.Problems) != 3 {
		t.Fatalf("%+v", u.Problems)
	}
}

func TestBools(t *testing.T) {
	for _, s := range []string{"1", "yes", "Y", "true", "t", "on"} {
		if v, ok := Bool(s); !v || !ok {
			t.Errorf("%s", s)
		}
	}
	for _, s := range []string{"0", "no", "n", "false", "f", "off"} {
		if v, ok := Bool(s); v || !ok {
			t.Errorf("%s", s)
		}
	}
	if _, ok := Bool("strict"); ok {
		t.Error("strict is not a boolean")
	}
}

func TestLastWinsAndEmptyResets(t *testing.T) {
	u := text(t, "[Service]\nProtectSystem=strict\nProtectSystem=full\nUMask=0077\nUMask=\nPrivateTmp=banana\n")
	if v, _ := u.Get("Service", "ProtectSystem", "no"); v != "full" {
		t.Fatalf("%q", v)
	}
	if v, a := u.Get("Service", "UMask", "0022"); v != "0022" || a == nil {
		t.Fatalf("an empty assignment resets to the default: %q", v)
	}
	if v, _ := u.GetBool("Service", "PrivateTmp", false); v {
		t.Fatal("an unreadable boolean is ignored, leaving the default")
	}
}

func TestIgnoredLinesKeepTheEarlierValue(t *testing.T) {
	u := text(t, "[Service]\nProtectSystem=strict\nProtectSystem=banana\nProtectHome=read-only\nProtectHome=\n"+
		"PrivateTmp=yes\nPrivateTmp=maybe\nPrivateDevices=yes\nPrivateDevices=\nUMask=0027\nUMask=\nUMask=99999\nUMask=17777\n")
	for k, want := range map[string]string{"ProtectSystem": "strict", "ProtectHome": "no", "PrivateTmp": "yes", "PrivateDevices": "yes", "UMask": "0027"} {
		if got := u.Effective(k); got != want {
			t.Errorf("%s: got %q want %q", k, got, want)
		}
	}
}

func TestDynamicUser(t *testing.T) {
	u := FromText("my-app.service", []byte("[Service]\nDynamicUser=yes\nProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nNoNewPrivileges=no\n"))
	for k, want := range map[string]string{"User": "my-app", "ProtectSystem": "strict", "ProtectHome": "read-only", "PrivateTmp": "yes",
		"NoNewPrivileges": "yes", "RestrictSUIDSGID": "yes", "PrivateDevices": "no"} {
		if got := u.Effective(k); got != want {
			t.Errorf("%s: got %q want %q", k, got, want)
		}
	}
	if got := FromText("x.service", []byte("[Service]\nDynamicUser=yes\nProtectHome=tmpfs\nUser=svc\n")); got.Effective("ProtectHome") != "tmpfs" || got.Effective("User") != "svc" {
		t.Fatal("an explicit ProtectHome= other than no, and an explicit User=, are kept")
	}
	for name, want := range map[string]string{"getty@tty1.service": "getty", "web_1-a.service": "web_1-a", "a.b.service": "", "9lives.service": ""} {
		if got := dynamicUserName(name); got != want {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func TestCapabilityReplaceRules(t *testing.T) {
	// The ambient set is "untouched" again once it is empty, so a "~" line replaces it.
	amb := text(t, "[Service]\nAmbientCapabilities=CAP_CHOWN\nAmbientCapabilities=~CAP_CHOWN\nAmbientCapabilities=~CAP_SYS_ADMIN\n").Capabilities("AmbientCapabilities")
	if amb.Has("cap_sys_admin") || !amb.Has("cap_chown") || !amb.Has("cap_kill") {
		t.Fatalf("%v", joinSorted(amb.Caps))
	}
	// The bounding set is touched after its first line, so later lines merge.
	b := text(t, "[Service]\nCapabilityBoundingSet=~CAP_KILL\nCapabilityBoundingSet=CAP_CHOWN\n").Capabilities("CapabilityBoundingSet")
	if b.All || b.Has("cap_kill") || !b.Has("cap_sys_admin") {
		t.Fatalf("%v", joinSorted(b.Caps))
	}
	if all := text(t, "[Service]\nCapabilityBoundingSet=CAP_CHOWN\nCapabilityBoundingSet=~\n").Capabilities("CapabilityBoundingSet"); !all.All {
		t.Fatal(`"~" alone is every capability`)
	}
	if c := text(t, "[Service]\nCapabilityBoundingSet=~\nCapabilityBoundingSet=~CAP_KILL\n").Capabilities("CapabilityBoundingSet"); c.All || c.Has("cap_kill") || !c.Has("cap_chown") {
		t.Fatal("a ~ line merging into the full set removes from it")
	}
}

func TestAddressFamiliesAfterNone(t *testing.T) {
	if got := text(t, "[Service]\nRestrictAddressFamilies=none\nRestrictAddressFamilies=~AF_PACKET\n").Effective("RestrictAddressFamilies"); got != "~AF_PACKET" {
		t.Fatalf("a line after none starts a fresh list: %q", got)
	}
}

func TestCapabilityBoundingSet(t *testing.T) {
	for _, c := range []struct {
		lines string
		all   bool
		caps  string
	}{
		{"", true, ""},
		{"CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_CHOWN", false, "cap_chown cap_net_bind_service"},
		{"CapabilityBoundingSet=CAP_CHOWN\nCapabilityBoundingSet=CAP_KILL", false, "cap_chown cap_kill"},
		{"CapabilityBoundingSet=", false, ""},
		{"CapabilityBoundingSet=CAP_CHOWN\nCapabilityBoundingSet=", false, ""},
		{"CapabilityBoundingSet=CAP_CHOWN CAP_KILL\nCapabilityBoundingSet=~CAP_KILL", false, "cap_chown"},
		{"CapabilityBoundingSet=", false, ""},
	} {
		got := text(t, "[Service]\n"+c.lines+"\n").Capabilities("CapabilityBoundingSet")
		if got.All != c.all || (!c.all && joinSorted(got.Caps) != c.caps) {
			t.Errorf("%q: all=%v caps=%q", c.lines, got.All, joinSorted(got.Caps))
		}
	}
	inv := text(t, "[Service]\nCapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_PTRACE\n").Capabilities("CapabilityBoundingSet")
	if inv.All || inv.Has("CAP_SYS_ADMIN") || !inv.Has("cap_chown") || !inv.Has("NET_BIND_SERVICE") {
		t.Fatalf("~ removes from the full set: %v", joinSorted(inv.Caps))
	}
	if amb := text(t, "[Service]\n").Capabilities("AmbientCapabilities"); amb.All || len(amb.Caps) != 0 {
		t.Fatal("no ambient capabilities unless granted")
	}
}

func TestAddressFamilies(t *testing.T) {
	for _, c := range []struct {
		lines, want string
	}{
		{"", ""},
		{"RestrictAddressFamilies=AF_UNIX AF_INET", "AF_INET AF_UNIX"},
		{"RestrictAddressFamilies=AF_UNIX\nRestrictAddressFamilies=AF_INET", "AF_INET AF_UNIX"},
		{"RestrictAddressFamilies=~AF_PACKET", "~AF_PACKET"},
		{"RestrictAddressFamilies=AF_UNIX AF_INET\nRestrictAddressFamilies=~AF_INET", "AF_UNIX"},
		{"RestrictAddressFamilies=AF_UNIX\nRestrictAddressFamilies=", ""},
		{"RestrictAddressFamilies=none", "none"},
	} {
		u := text(t, "[Service]\n"+c.lines+"\n")
		if got := u.Effective("RestrictAddressFamilies"); got != c.want {
			t.Errorf("%q: got %q want %q", c.lines, got, c.want)
		}
	}
	f := text(t, "[Service]\nRestrictAddressFamilies=~AF_PACKET\n").AddressFamilies()
	if f.Allows("AF_PACKET") || !f.Allows("AF_INET") {
		t.Fatal("deny list")
	}
}

func TestCommands(t *testing.T) {
	u := text(t, "[Service]\nExecStartPre=-+/bin/a x\nExecStartPre=\nExecStartPre=!!/bin/b\nExecStart=@/bin/c argv0 y\n")
	pre := u.Commands("ExecStartPre")
	if len(pre) != 1 || pre[0].Path != "/bin/b" || pre[0].Prefixes != "!!" {
		t.Fatalf("an empty assignment clears the list: %+v", pre)
	}
	if c := u.Commands("ExecStart"); c[0].Prefixes != "@" || c[0].Path != "/bin/c" {
		t.Fatalf("%+v", c)
	}
}

func TestEffectiveSpellings(t *testing.T) {
	u := text(t, "[Service]\nProtectSystem=true\nProtectHome=read-only\nUMask=77\nNoNewPrivileges=on\n")
	for k, want := range map[string]string{"ProtectSystem": "yes", "ProtectHome": "read-only", "UMask": "0077", "NoNewPrivileges": "yes",
		"PrivateTmp": "no", "User": "", "CapabilityBoundingSet": "all", "AmbientCapabilities": ""} {
		if got := u.Effective(k); got != want {
			t.Errorf("%s: got %q want %q", k, got, want)
		}
	}
}

func TestDropinDirs(t *testing.T) {
	got := dropinDirs("a-b-c.service")
	want := []string{"a-b-c.service.d", "a-b-.service.d", "a-.service.d", "service.d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if got := dropinDirs("getty@tty1.service"); !reflect.DeepEqual(got, []string{"getty@tty1.service.d", "getty@.service.d", "service.d"}) {
		t.Fatalf("%v", got)
	}
}

// --- loading from a file system --------------------------------------------------------------

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPrecedence(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/lib/systemd/system/app.service", "[Service]\nUser=packaged\n")
	write(t, root, "etc/systemd/system/app.service", "[Service]\nUser=admin\n")
	// The same drop-in name in /etc hides the one in /usr/lib; all others apply in name order.
	write(t, root, "usr/lib/systemd/system/app.service.d/10-a.conf", "[Service]\nPrivateTmp=no\n")
	write(t, root, "etc/systemd/system/app.service.d/10-a.conf", "[Service]\nPrivateTmp=yes\n")
	write(t, root, "usr/lib/systemd/system/app.service.d/20-b.conf", "[Service]\nUMask=0077\n")
	write(t, root, "usr/lib/systemd/system/app.service.d/05-early.conf", "[Service]\nUMask=0000\n")
	write(t, root, "etc/systemd/system/service.d/30-all.conf", "[Service]\nProtectClock=yes\n")
	write(t, root, "etc/systemd/system/app.service.d/note.txt", "[Service]\nUser=ignored\n")
	u, err := Load(root, "app.service")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := u.Get("Service", "User", ""); v != "admin" {
		t.Fatalf("/etc's unit file replaces /usr/lib's: %q", v)
	}
	if v, _ := u.GetBool("Service", "PrivateTmp", false); !v {
		t.Fatal("the /etc drop-in with the same name wins")
	}
	if u.Effective("UMask") != "0077" || u.Effective("ProtectClock") != "yes" {
		t.Fatalf("other drop-ins still apply: %v", u.Files)
	}
	var names []string
	for _, f := range u.Files[1:] {
		names = append(names, filepath.Base(f))
	}
	if !reflect.DeepEqual(names, []string{"05-early.conf", "10-a.conf", "20-b.conf", "30-all.conf"}) {
		t.Fatalf("drop-ins apply in file name order: %v", u.Files)
	}
}

func TestADropInOnlyUnitAndAMissingOne(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/systemd/system/x.service.d/a.conf", "[Service]\nUser=y\n")
	if u, err := Load(root, "x.service"); err != nil || u.Path != "" {
		t.Fatalf("%v %+v", err, u)
	}
	if _, err := Load(root, "nope.service"); err == nil {
		t.Fatal("want an error")
	}
}

func TestMasked(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc", "systemd", "system")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(dir, "m.service")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	write(t, root, "usr/lib/systemd/system/m.service", "[Service]\nUser=x\n")
	u, err := Load(root, "m.service")
	if err != nil || !u.Masked {
		t.Fatalf("%v %+v", err, u)
	}
}

func TestLoadFileAndUnits(t *testing.T) {
	root := t.TempDir()
	write(t, root, "repo/app.service", "[Service]\nUser=a\n")
	write(t, root, "repo/app.service.d/override.conf", "[Service]\nUser=b\n")
	u, err := LoadFile(filepath.Join(root, "repo", "app.service"))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := u.Get("Service", "User", ""); v != "b" {
		t.Fatalf("%q", v)
	}
	write(t, root, "usr/lib/systemd/system/b.service", "[Service]\n")
	write(t, root, "etc/systemd/system/a.service", "[Service]\n")
	write(t, root, "usr/lib/systemd/system/a.service", "[Service]\n")
	write(t, root, "etc/systemd/system/a.socket", "[Socket]\n")
	if got := Units(root); !reflect.DeepEqual(got, []string{"a.service", "b.service"}) {
		t.Fatalf("%v", got)
	}
	big := filepath.Join(root, "big.service")
	if err := os.WriteFile(big, []byte(strings.Repeat("#", maxFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(big); err == nil {
		t.Fatal("oversized file")
	}
}

func FuzzParse(f *testing.F) {
	f.Add("[Service]\nExecStart=/bin/a \\\n b\nCapabilityBoundingSet=~CAP_X\n")
	f.Add("[Service]\nRestrictAddressFamilies=AF_UNIX\nRestrictAddressFamilies=~AF_UNIX\n")
	f.Fuzz(func(t *testing.T, s string) {
		u := FromText("f.service", []byte(s))
		for _, k := range EffectiveKeys {
			u.Effective(k)
		}
		u.Commands("ExecStart")
	})
}
