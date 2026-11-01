package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

const root = "../../testdata/root"

func TestEveryServiceUnderARoot(t *testing.T) {
	code, out, _ := run(t, "", "--root", root)
	if code != 1 || !strings.Contains(out, "3 unit(s)") || strings.Contains(out, "uw-hardened.service\n") || !strings.Contains(out, "UW021") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestNamedUnitsAndEffective(t *testing.T) {
	code, out, _ := run(t, "", "--root", root, "--effective", "uw-webapp.service")
	if code != 0 || !strings.Contains(out, "ProtectSystem=no\n") || !strings.Contains(out, "NoNewPrivileges=yes\n") ||
		!strings.Contains(out, "CapabilityBoundingSet=cap_net_bind_service\n") {
		t.Fatalf("%s", out)
	}
}

func TestFilesDirectoriesAndStdin(t *testing.T) {
	dir := filepath.Join(root, "usr", "lib", "systemd", "system")
	if code, out, _ := run(t, "", dir, "--fail-on", "info"); code != 1 || !strings.Contains(out, "3 unit(s)") {
		t.Fatalf("%d %s", code, out)
	}
	if code, out, _ := run(t, "", filepath.Join(dir, "uw-hardened.service"), "--fail-on", "info"); code != 0 || !strings.Contains(out, "no findings") {
		t.Fatalf("%d %s", code, out)
	}
	// Read as a lone file, uw-backup misses the uw-.service.d prefix drop-in that sets NoNewPrivileges.
	if _, out, _ := run(t, "", filepath.Join(dir, "uw-backup.service")); !strings.Contains(out, "UW010") {
		t.Fatalf("%s", out)
	}
	if _, out, _ := run(t, "", "--root", root, "uw-backup.service"); strings.Contains(out, "UW010") {
		t.Fatalf("%s", out)
	}
	if code, out, _ := run(t, "[Service]\nExecStart=+/bin/x\n", "-"); code != 1 || !strings.Contains(out, "UW002") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestFailOnAndJSON(t *testing.T) {
	unit := "[Service]\nDynamicUser=yes\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n"
	for level, want := range map[string]int{"medium": 0, "low": 1, "none": 0} {
		if code, _, _ := run(t, unit, "-", "--fail-on", level); code != want {
			t.Errorf("--fail-on %s: %d", level, code)
		}
	}
	_, out, _ := run(t, unit, "-", "--json")
	var res struct {
		Units    int `json:"units"`
		Findings []struct{ ID, Severity, Unit, Message string }
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Units != 1 || len(res.Findings) == 0 {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"nothing":       {},
		"bad fail-on":   {"--fail-on", "x", "-"},
		"unknown":       {"--nope", "-"},
		"missing file":  {filepath.Join(t.TempDir(), "x.service")},
		"missing unit":  {"--root", root, "nope.service"},
		"empty root":    {"--root", t.TempDir()},
		"no unit files": {t.TempDir()},
	} {
		if code, _, errOut := run(t, "", args...); code != 2 || errOut == "" {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := run(t, "", "--version"); code != 0 || !strings.HasPrefix(out, "unitwarden ") {
		t.Fatal(out)
	}
	if code, out, _ := run(t, "", "--help"); code != 0 || !strings.Contains(out, "usage:") {
		t.Fatal(out)
	}
}
