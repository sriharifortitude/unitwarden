// Package cli is unitwarden's command line.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sriharifortitude/unitwarden/internal/rules"
	"github.com/sriharifortitude/unitwarden/internal/unit"
)

// Version is the release.
var Version = "0.1.0"

const usage = `unitwarden: judge how much a systemd service could do if it were compromised.

usage: unitwarden [flags] TARGET...
       unitwarden --root DIR [UNIT...]

Without --root, each TARGET is a unit file (its "<file>.d/" drop-ins are read too), a
directory of them, or - for standard input. With --root, units are looked up by name on the
systemd search path under DIR (use / for this machine), with every drop-in that applies; with
no names, every service there is checked.

flags:
  --root DIR       look units up on the search path under DIR
  --effective      print the settings in force for each unit, as systemctl show spells them
  --fail-on LEVEL  exit 1 at or above: critical, high, medium (default), low, info, none
  --json           machine-readable findings
  --version

exit status: 0 nothing at or above --fail-on, 1 at least one finding is, 2 usage error or unreadable input
`

// Run executes the command and returns the exit status.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("unitwarden", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", "", "")
	effective := fs.Bool("effective", false, "")
	failOn := fs.String("fail-on", "medium", "")
	asJSON := fs.Bool("json", false, "")
	showVersion := fs.Bool("version", false, "")
	help := fs.Bool("help", false, "")

	var targets []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			fmt.Fprintf(stderr, "unitwarden: %v\n\n%s", err, usage)
			return 2
		}
		rest = fs.Args()
		if len(rest) > 0 {
			targets = append(targets, rest[0])
			rest = rest[1:]
		}
	}
	switch {
	case *help:
		fmt.Fprint(stdout, usage)
		return 0
	case *showVersion:
		fmt.Fprintf(stdout, "unitwarden %s\n", Version)
		return 0
	case len(targets) == 0 && *root == "":
		fmt.Fprint(stderr, usage)
		return 2
	case *failOn != "none" && rules.Rank(*failOn) == len(rules.Severities):
		fmt.Fprintf(stderr, "unitwarden: --fail-on must be critical, high, medium, low, info or none, not %q\n", *failOn)
		return 2
	}

	units, err := load(*root, targets, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "unitwarden: %v\n", err)
		return 2
	}
	if *effective {
		for i, u := range units {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			fmt.Fprintf(stdout, "# %s\n", u.Name)
			for _, k := range unit.EffectiveKeys {
				fmt.Fprintf(stdout, "%s=%s\n", k, u.Effective(k))
			}
		}
		return 0
	}

	var findings []rules.Finding
	for _, u := range units {
		findings = append(findings, rules.Check(u)...)
	}
	if *asJSON {
		if findings == nil {
			findings = []rules.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"units": len(units), "findings": findings}); err != nil {
			return 2
		}
	} else {
		fmt.Fprint(stdout, Render(len(units), findings))
	}
	for _, f := range findings {
		if *failOn != "none" && rules.Rank(f.Severity) <= rules.Rank(*failOn) {
			return 1
		}
	}
	return 0
}

func load(root string, targets []string, stdin io.Reader) ([]*unit.Unit, error) {
	var out []*unit.Unit
	if root != "" {
		names := targets
		if len(names) == 0 {
			names = unit.Units(root)
			if len(names) == 0 {
				return nil, fmt.Errorf("no services found under %s", root)
			}
		}
		for _, n := range names {
			u, err := unit.Load(root, n)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
		return out, nil
	}
	for _, t := range targets {
		if t == "-" {
			data, err := io.ReadAll(io.LimitReader(stdin, 1<<20+1))
			if err != nil || len(data) > 1<<20 {
				return nil, fmt.Errorf("standard input is unreadable or over 1 MiB")
			}
			out = append(out, unit.FromText("stdin.service", data))
			continue
		}
		info, err := os.Stat(t)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			u, err := unit.LoadFile(t)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
			continue
		}
		entries, err := os.ReadDir(t)
		if err != nil {
			return nil, err
		}
		var files []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".service") {
				files = append(files, filepath.Join(t, e.Name()))
			}
		}
		sort.Strings(files)
		for _, f := range files {
			u, err := unit.LoadFile(f)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no service files found")
	}
	return out, nil
}

// Render formats findings as text, grouped by unit.
func Render(units int, findings []rules.Finding) string {
	var b strings.Builder
	last := ""
	for _, f := range findings {
		if f.Unit != last {
			if last != "" {
				b.WriteByte('\n')
			}
			fmt.Fprintf(&b, "%s\n", f.Unit)
			last = f.Unit
		}
		where := ""
		if f.Line > 0 {
			where = fmt.Sprintf("  (%s:%d)", f.File, f.Line)
		}
		fmt.Fprintf(&b, "  %s %-8s %s%s\n", f.ID, f.Severity, f.Message, where)
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range rules.Severities {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	summary := "no findings"
	if len(parts) > 0 {
		summary = strings.Join(parts, ", ")
	}
	if len(findings) > 0 {
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "%d unit(s); %s\n", units, summary)
	return b.String()
}
