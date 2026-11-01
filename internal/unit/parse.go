// Package unit reads systemd unit files the way systemd does: the main file found first on the
// search path, then every drop-in in filename order, with later assignments winning and empty
// assignments resetting lists.
package unit

import (
	"bufio"
	"bytes"
	"strings"
)

// Assignment is one "Key=value" line.
type Assignment struct {
	Section string
	Key     string
	Value   string
	File    string
	Line    int
}

// Problem is a line systemd would not understand.
type Problem struct {
	File    string
	Line    int
	Message string
}

// parse reads one unit file or drop-in. Continuation lines end in a backslash; a comment line
// inside a continuation is skipped, as systemd does.
func parse(name string, data []byte) ([]Assignment, []Problem) {
	var out []Assignment
	var problems []Problem
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	section := ""
	lineNo := 0
	var pending strings.Builder
	pendingLine := 0
	flush := func(text string, line int) {
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		if strings.HasPrefix(text, "[") {
			if !strings.HasSuffix(text, "]") {
				problems = append(problems, Problem{name, line, "a section header without a closing ]"})
				return
			}
			section = strings.TrimSpace(text[1 : len(text)-1])
			return
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			problems = append(problems, Problem{name, line, "a line that is neither a section header nor Key=value: systemd ignores it"})
			return
		}
		if section == "" {
			problems = append(problems, Problem{name, line, "an assignment before any [Section]: systemd ignores it"})
			return
		}
		out = append(out, Assignment{Section: section, Key: strings.TrimSpace(key), Value: strings.TrimSpace(value), File: name, Line: line})
	}
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if pending.Len() > 0 && (strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";")) {
			continue
		}
		if pending.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";")) {
			continue
		}
		if pending.Len() == 0 {
			pendingLine = lineNo
		}
		if strings.HasSuffix(raw, `\`) {
			pending.WriteString(strings.TrimSuffix(raw, `\`))
			pending.WriteByte(' ')
			continue
		}
		pending.WriteString(raw)
		flush(pending.String(), pendingLine)
		pending.Reset()
	}
	if pending.Len() > 0 {
		flush(pending.String(), pendingLine)
	}
	return out, problems
}

// Bool reads systemd's boolean spellings. ok is false for anything else.
func Bool(s string) (value, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "yes", "y", "true", "t", "on":
		return true, true
	case "0", "no", "n", "false", "f", "off":
		return false, true
	}
	return false, false
}
