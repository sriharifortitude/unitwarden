package unit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxFileBytes = 1 << 20

// SearchPath is the system unit search path, highest priority first, as systemd(1) lists it
// for the directories that hold files written by people and packages.
var SearchPath = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// Unit is a unit with its drop-ins applied.
type Unit struct {
	Name string
	// Path is the main unit file, or empty when only drop-ins were found.
	Path string
	// Masked is true when the unit file is a link to /dev/null.
	Masked bool
	// Assignments are every line from the main file and the drop-ins, in the order systemd applies them.
	Assignments []Assignment
	Files       []string
	Problems    []Problem
}

// Type is the unit's suffix: "service", "socket", ...
func (u *Unit) Type() string {
	if i := strings.LastIndexByte(u.Name, '.'); i >= 0 {
		return u.Name[i+1:]
	}
	return ""
}

// Load finds a unit by name under root (which may be "/" or a copy of another machine's
// file system) and applies its drop-ins.
func Load(root, name string) (*Unit, error) {
	u := &Unit{Name: name}
	for _, dir := range SearchPath {
		p := filepath.Join(root, filepath.FromSlash(dir), name)
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Readlink(p); err == nil && filepath.ToSlash(target) == "/dev/null" {
				u.Masked = true
				u.Path = filepath.ToSlash(p)
				return u, nil
			}
		}
		u.Path = filepath.ToSlash(p)
		break
	}
	if u.Path != "" {
		if err := u.add(u.Path); err != nil {
			return nil, err
		}
	}
	dropins := dropinDirs(name)
	// Drop-in file name -> path; the first one seen wins. The search path is the outer loop:
	// systemd 259 lets /etc/systemd/system/a-.service.d/x.conf hide
	// /usr/lib/systemd/system/a-b.service.d/x.conf (scripts/differential.sh checks this).
	chosen := map[string]string{}
	for _, dir := range SearchPath {
		for _, d := range dropins {
			entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir), d))
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
					continue
				}
				if _, seen := chosen[e.Name()]; !seen {
					chosen[e.Name()] = filepath.ToSlash(filepath.Join(root, filepath.FromSlash(dir), d, e.Name()))
				}
			}
		}
	}
	if u.Path == "" && len(chosen) == 0 {
		return nil, fmt.Errorf("unit %s not found under %s", name, root)
	}
	names := make([]string, 0, len(chosen))
	for n := range chosen {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := u.add(chosen[n]); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// LoadFile reads one unit file and the drop-ins in "<file>.d/" beside it, for checking a file
// in a repository before it is installed.
func LoadFile(path string) (*Unit, error) {
	u := &Unit{Name: filepath.Base(path), Path: filepath.ToSlash(path)}
	if err := u.add(path); err != nil {
		return nil, err
	}
	entries, _ := os.ReadDir(path + ".d")
	var confs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
			confs = append(confs, e.Name())
		}
	}
	sort.Strings(confs)
	for _, c := range confs {
		if err := u.add(filepath.Join(path+".d", c)); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// dropinDirs lists the drop-in directory names that apply to a unit, most specific first: the
// unit's own, then the prefix directories of a dashed name ("a-b-c.service" also reads
// "a-b-.service.d" and "a-.service.d"), then the type-wide one ("service.d").
func dropinDirs(name string) []string {
	out := []string{name + ".d"}
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return out
	}
	base, suffix := name[:dot], name[dot:]
	if at := strings.IndexByte(base, '@'); at >= 0 {
		// A template instance also reads the template's drop-ins: foo@bar.service -> foo@.service.d
		out = append(out, base[:at+1]+suffix+".d")
		base = base[:at]
	}
	parts := strings.Split(base, "-")
	for i := len(parts) - 1; i >= 1; i-- {
		out = append(out, strings.Join(parts[:i], "-")+"-"+suffix+".d")
	}
	return append(out, strings.TrimPrefix(suffix, ".")+".d")
}

func (u *Unit) add(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > maxFileBytes {
		return fmt.Errorf("%s is over 1 MiB; a unit file that large is not read", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	name := filepath.ToSlash(path)
	as, ps := parse(name, data)
	u.Files = append(u.Files, name)
	u.Assignments = append(u.Assignments, as...)
	u.Problems = append(u.Problems, ps...)
	return nil
}

// FromText parses unit text that comes from nowhere on disk, such as standard input.
func FromText(name string, data []byte) *Unit {
	u := &Unit{Name: name, Path: name}
	as, ps := parse(name, data)
	u.Files = []string{name}
	u.Assignments, u.Problems = as, ps
	return u
}

// Units lists every *.service file found on the search path under root, by name.
func Units(root string) []string {
	seen := map[string]bool{}
	var out []string
	for _, dir := range SearchPath {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, ".service") && !seen[n] && !e.IsDir() {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}
